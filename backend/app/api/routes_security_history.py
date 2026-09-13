"""Security history API: filterable history, single events, review view.

All rows are owner-scoped (explicit filter + RLS). Responses are
metadata-only — no tokens, no plaintext secrets, no chat content.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.security import CurrentUser, get_current_user
from app.db.models import (
    ConnectorSettings,
    EmailConnectorAccount,
    QuarantinedItem,
    SecurityEvent,
)
from app.db.session import get_db
from app.schemas.security_history import (
    QuarantineReviewResponse,
    ReviewAvailableActions,
    ReviewMessageMeta,
    SecurityEventRead,
    SecurityHistoryListResponse,
)
from app.services.security_history_service import serialize_event

logger = logging.getLogger("cyberguard.security_history.api")

router = APIRouter(prefix="/security-history", tags=["Security History"])
# Review view lives at the spec path /api/v1/quarantine/{item_id}/review.
review_router = APIRouter(prefix="/quarantine", tags=["Security History"])

_REVIEW_BODY_PREVIEW_CHARS = 400


@router.get("", response_model=SecurityHistoryListResponse)
async def list_security_history(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    event_type: Optional[str] = Query(default=None),
    actor_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    sender_email: Optional[str] = Query(default=None),
    from_ts: Optional[datetime] = Query(default=None, alias="from"),
    to_ts: Optional[datetime] = Query(default=None, alias="to"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> SecurityHistoryListResponse:
    """Owner-scoped security history, newest first, with filters."""
    query = select(SecurityEvent).where(SecurityEvent.owner_user_id == user.id)
    count_query = select(func.count()).select_from(SecurityEvent).where(
        SecurityEvent.owner_user_id == user.id
    )

    filters = []
    if event_type:
        filters.append(SecurityEvent.event_type == event_type)
    if actor_type:
        filters.append(SecurityEvent.actor_type == actor_type)
    if severity:
        filters.append(SecurityEvent.severity == severity)
    if sender_email:
        filters.append(SecurityEvent.sender_email.ilike(f"%{sender_email.strip()}%"))
    if from_ts:
        filters.append(SecurityEvent.created_at >= from_ts)
    if to_ts:
        filters.append(SecurityEvent.created_at <= to_ts)

    for f in filters:
        query = query.where(f)
        count_query = count_query.where(f)

    total = (await db.execute(count_query)).scalar() or 0
    rows = (
        await db.execute(
            query.order_by(SecurityEvent.created_at.desc()).offset(offset).limit(limit)
        )
    ).scalars().all()

    return SecurityHistoryListResponse(
        items=[SecurityEventRead(**serialize_event(e)) for e in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{event_id}", response_model=SecurityEventRead)
async def get_security_event(
    event_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SecurityEventRead:
    result = await db.execute(
        select(SecurityEvent).where(
            SecurityEvent.id == event_id, SecurityEvent.owner_user_id == user.id
        )
    )
    event = result.scalar_one_or_none()
    if event is None:
        raise NotFoundError("Security event", event_id)
    return SecurityEventRead(**serialize_event(event))


@review_router.get("/{item_id}/review", response_model=QuarantineReviewResponse)
async def review_quarantined_item(
    item_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> QuarantineReviewResponse:
    """The review record for a flagged email: item + message metadata +
    stored ScanResult + the full ordered event chain + available actions."""
    result = await db.execute(
        select(QuarantinedItem).where(
            QuarantinedItem.id == item_id, QuarantinedItem.owner_user_id == user.id
        )
    )
    item = result.scalar_one_or_none()
    if item is None:
        raise NotFoundError("Quarantined item", item_id)

    scan_result = item.scan_result_json or {}

    # Ordered event chain for this message (scan -> quarantine -> ...).
    chain = []
    if item.provider_message_id:
        chain_rows = (
            await db.execute(
                select(SecurityEvent)
                .where(
                    SecurityEvent.owner_user_id == user.id,
                    SecurityEvent.provider_message_id == item.provider_message_id,
                )
                .order_by(SecurityEvent.created_at.asc())
            )
        ).scalars().all()
        chain = [SecurityEventRead(**serialize_event(e)) for e in chain_rows]

    connector = (
        await db.execute(
            select(EmailConnectorAccount).where(EmailConnectorAccount.id == item.connector_id)
        )
    ).scalar_one_or_none()
    settings = (
        await db.execute(
            select(ConnectorSettings).where(ConnectorSettings.connector_id == item.connector_id)
        )
    ).scalar_one_or_none()
    permanent_delete = bool(settings.permanent_delete_enabled) if settings else False
    connector_ready = connector is not None and connector.status == "connected"

    can_act = item.status == "quarantined" and connector_ready
    available_actions = ReviewAvailableActions(
        release=can_act,
        keep=can_act,
        delete=item.status in ("quarantined", "released") and connector_ready,
        # permanent_delete_enabled=false → delete is offered as trash-only.
        delete_mode="permanent" if permanent_delete else ("trash" if item.status in ("quarantined", "released") and connector_ready else None),
        connector_ready=connector_ready,
    )

    message_meta = ReviewMessageMeta(
        provider_message_id=item.provider_message_id,
        provider="gmail",
        sender_email=item.sender_email,
        subject=scan_result.get("subject"),
        received_at=scan_result.get("received_at"),
        body_preview=None,  # bodies are not stored in history; fetch via analysis endpoint if needed
    )

    return QuarantineReviewResponse(
        item={
            "id": item.id,
            "connector_id": item.connector_id,
            "provider_message_id": item.provider_message_id,
            "sender_email": item.sender_email,
            "reason": item.reason,
            "severity": item.severity,
            "status": item.status,
            "quarantined_at": item.quarantined_at.isoformat() if item.quarantined_at else None,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            "last_error": item.last_error,
        },
        message=message_meta,
        scan_result=scan_result or None,
        event_chain=chain,
        available_actions=available_actions,
    )

