"""Enforcement API: quarantine queue, blocked senders, manual overrides.

All rows carry owner_user_id and are filtered by the caller (RLS doubles the
guarantee). Manual actions perform real Gmail operations; failures are
recorded on the row and returned with honest error envelopes.
"""

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, NotFoundError, PermissionDeniedError
from app.core.security import CurrentUser, get_current_user
from app.db.models import BlockedSender, ConnectorSettings, QuarantinedItem
from app.db.session import get_db
from app.services.action_engine import get_or_create_settings
from app.services.connectors.token_manager import TokenRefreshError, get_valid_access_token
from app.services.email_providers.base import EmailProviderError
from app.services.email_providers.gmail import gmail_provider
from app.services.security_history_service import record_event

logger = logging.getLogger("cyberguard.enforcement.api")

router = APIRouter(prefix="/enforcement", tags=["Enforcement"])


class QuarantinedItemRead(BaseModel):
    id: str
    connector_id: str
    provider_message_id: str
    sender_email: str
    reason: str
    severity: str
    scan_result: dict[str, Any]
    quarantined_at: Optional[str] = None
    expires_at: Optional[str] = None
    status: str
    last_error: Optional[str] = None


class QuarantineListResponse(BaseModel):
    items: list[QuarantinedItemRead]


class BlockedSenderRead(BaseModel):
    id: str
    connector_id: str
    sender_email: str
    provider_rule_id: Optional[str] = None
    reason: str
    blocked_at: Optional[str] = None
    expires_at: Optional[str] = None
    status: str
    last_error: Optional[str] = None


class BlockedSenderListResponse(BaseModel):
    items: list[BlockedSenderRead]


class EnforcementActionResponse(BaseModel):
    id: str
    status: str
    provider_operation_status: str
    message: Optional[str] = None


def _iso(dt) -> Optional[str]:
    return dt.isoformat() if dt else None


def _serialize_item(item: QuarantinedItem) -> QuarantinedItemRead:
    return QuarantinedItemRead(
        id=item.id,
        connector_id=item.connector_id,
        provider_message_id=item.provider_message_id,
        sender_email=item.sender_email,
        reason=item.reason,
        severity=item.severity,
        scan_result=item.scan_result_json or {},
        quarantined_at=_iso(item.quarantined_at),
        expires_at=_iso(item.expires_at),
        status=item.status,
        last_error=item.last_error,
    )


def _serialize_block(block: BlockedSender) -> BlockedSenderRead:
    return BlockedSenderRead(
        id=block.id,
        connector_id=block.connector_id,
        sender_email=block.sender_email,
        provider_rule_id=block.provider_rule_id,
        reason=block.reason,
        blocked_at=_iso(block.blocked_at),
        expires_at=_iso(block.expires_at),
        status=block.status,
        last_error=block.last_error,
    )


def _provider_error(exc: Exception) -> AppError:
    error_class = getattr(exc, "error_class", None) or "api_error"
    detail = getattr(exc, "message", str(exc))
    if error_class == "reauth_required":
        return PermissionDeniedError("Mailbox authorization expired — reconnect this connector.")
    if error_class == "insufficient_scope":
        return AppError(
            "Action failed: Insufficient permissions. Please reconnect Gmail and "
            "grant settings access.",
            code="insufficient_scope",
            status_code=403,
        )
    return AppError(f"Action failed ({error_class}): {detail}", code="provider_error", status_code=502)


async def _load_item(db: AsyncSession, item_id: str, user: CurrentUser) -> QuarantinedItem:
    result = await db.execute(
        select(QuarantinedItem).where(
            QuarantinedItem.id == item_id, QuarantinedItem.owner_user_id == user.id
        )
    )
    item = result.scalar_one_or_none()
    if item is None:
        raise NotFoundError("Quarantined item", item_id)
    return item


async def _load_block(db: AsyncSession, block_id: str, user: CurrentUser) -> BlockedSender:
    result = await db.execute(
        select(BlockedSender).where(
            BlockedSender.id == block_id, BlockedSender.owner_user_id == user.id
        )
    )
    block = result.scalar_one_or_none()
    if block is None:
        raise NotFoundError("Blocked sender", block_id)
    return block


@router.get("/quarantine", response_model=QuarantineListResponse)
async def list_quarantine(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> QuarantineListResponse:
    items = (
        await db.execute(
            select(QuarantinedItem)
            .where(QuarantinedItem.owner_user_id == user.id)
            .order_by(QuarantinedItem.quarantined_at.desc())
        )
    ).scalars().all()
    return QuarantineListResponse(items=[_serialize_item(i) for i in items])


@router.post("/quarantine/{item_id}/release", response_model=EnforcementActionResponse)
async def release_quarantined(
    item_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EnforcementActionResponse:
    item = await _load_item(db, item_id, user)
    if item.status != "quarantined":
        raise AppError(f"Item is not quarantined (status: {item.status}).", code="invalid_state", status_code=400)

    from app.db.models import EmailConnectorAccount

    connector = (
        await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == item.connector_id))
    ).scalar_one_or_none()
    if connector is None:
        raise NotFoundError("Email connector", item.connector_id)

    try:
        token = await get_valid_access_token(connector, db)
        label_id = await gmail_provider.ensure_quarantine_label(token)
        await gmail_provider.release_message(token, item.provider_message_id, label_id)
    except (EmailProviderError, TokenRefreshError) as exc:
        item.last_error = f"{getattr(exc, 'error_class', 'api_error')}: {getattr(exc, 'message', exc)}"
        await db.commit()
        raise _provider_error(exc) from exc

    item.status = "released"
    item.last_error = None
    await db.commit()
    await record_event(
        db,
        owner_user_id=user.id,
        event_type="release",
        actor_type="user",
        connector_id=item.connector_id,
        provider="gmail",
        provider_message_id=item.provider_message_id,
        sender_email=item.sender_email,
        subject=(item.scan_result_json or {}).get("subject"),
        severity=item.severity,
        score=(item.scan_result_json or {}).get("overall_score"),
        action_requested="release",
        action_performed="release_message",
        operation_status="success",
        operation_detail="User released the message back to the inbox",
        quarantined_item_id=item.id,
    )
    return EnforcementActionResponse(id=item.id, status=item.status, provider_operation_status="success",
                                     message="Message released back to the inbox.")


@router.post("/quarantine/{item_id}/delete", response_model=EnforcementActionResponse)
async def delete_quarantined(
    item_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EnforcementActionResponse:
    item = await _load_item(db, item_id, user)
    if item.status not in ("quarantined", "released"):
        raise AppError(f"Item cannot be deleted (status: {item.status}).", code="invalid_state", status_code=400)

    from app.db.models import EmailConnectorAccount

    connector = (
        await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == item.connector_id))
    ).scalar_one_or_none()
    if connector is None:
        raise NotFoundError("Email connector", item.connector_id)

    settings_result = await db.execute(
        select(ConnectorSettings).where(ConnectorSettings.connector_id == connector.id)
    )
    settings = settings_result.scalar_one_or_none()
    permanent = bool(settings.permanent_delete_enabled) if settings else False

    try:
        token = await get_valid_access_token(connector, db)
        await gmail_provider.delete_message(token, item.provider_message_id, permanent=permanent)
    except (EmailProviderError, TokenRefreshError) as exc:
        item.last_error = f"{getattr(exc, 'error_class', 'api_error')}: {getattr(exc, 'message', exc)}"
        await db.commit()
        raise _provider_error(exc) from exc

    item.status = "deleted"
    item.last_error = None
    await db.commit()
    await record_event(
        db,
        owner_user_id=user.id,
        event_type="delete",
        actor_type="user",
        connector_id=item.connector_id,
        provider="gmail",
        provider_message_id=item.provider_message_id,
        sender_email=item.sender_email,
        subject=(item.scan_result_json or {}).get("subject"),
        severity=item.severity,
        score=(item.scan_result_json or {}).get("overall_score"),
        action_requested="delete",
        action_performed="permanent_delete" if permanent else "trash",
        operation_status="success",
        operation_detail="Message permanently deleted at Gmail." if permanent else "Message moved to Gmail trash.",
        quarantined_item_id=item.id,
    )
    return EnforcementActionResponse(
        id=item.id,
        status=item.status,
        provider_operation_status="success",
        message="Message permanently deleted." if permanent else "Message moved to Gmail trash.",
    )


@router.post("/quarantine/{item_id}/keep", response_model=EnforcementActionResponse)
async def keep_quarantined(
    item_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EnforcementActionResponse:
    """Keep a quarantined item as-is (manual review outcome, no provider action)."""
    item = await _load_item(db, item_id, user)
    if item.status != "quarantined":
        raise AppError(f"Item is not quarantined (status: {item.status}).", code="invalid_state", status_code=400)
    await record_event(
        db,
        owner_user_id=user.id,
        event_type="keep",
        actor_type="user",
        connector_id=item.connector_id,
        provider="gmail",
        provider_message_id=item.provider_message_id,
        sender_email=item.sender_email,
        subject=(item.scan_result_json or {}).get("subject"),
        severity=item.severity,
        score=(item.scan_result_json or {}).get("overall_score"),
        action_requested="keep",
        action_performed="none",
        operation_status="success",
        operation_detail="User reviewed the item and kept it quarantined; no mailbox change",
        quarantined_item_id=item.id,
    )
    return EnforcementActionResponse(id=item.id, status=item.status, provider_operation_status="success",
                                     message="Item kept in quarantine.")


@router.get("/blocked-senders", response_model=BlockedSenderListResponse)
async def list_blocked_senders(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> BlockedSenderListResponse:
    blocks = (
        await db.execute(
            select(BlockedSender)
            .where(BlockedSender.owner_user_id == user.id)
            .order_by(BlockedSender.blocked_at.desc())
        )
    ).scalars().all()
    return BlockedSenderListResponse(items=[_serialize_block(b) for b in blocks])


@router.post("/blocked-senders/{block_id}/release", response_model=EnforcementActionResponse)
async def release_blocked_sender(
    block_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EnforcementActionResponse:
    block = await _load_block(db, block_id, user)
    if block.status != "blocked":
        raise AppError(f"Sender is not blocked (status: {block.status}).", code="invalid_state", status_code=400)

    from app.db.models import EmailConnectorAccount

    connector = (
        await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == block.connector_id))
    ).scalar_one_or_none()
    if connector is None:
        raise NotFoundError("Email connector", block.connector_id)

    try:
        token = await get_valid_access_token(connector, db)
        if block.provider_rule_id:
            await gmail_provider.delete_sender_rule(token, block.provider_rule_id)
        else:
            # Rule creation had failed earlier; nothing to remove at Google.
            pass
    except (EmailProviderError, TokenRefreshError) as exc:
        block.last_error = f"{getattr(exc, 'error_class', 'api_error')}: {getattr(exc, 'message', exc)}"
        await db.commit()
        raise _provider_error(exc) from exc

    block.status = "released"
    block.last_error = None
    await db.commit()
    await record_event(
        db,
        owner_user_id=user.id,
        event_type="sender_release",
        actor_type="user",
        connector_id=block.connector_id,
        provider="gmail",
        sender_email=block.sender_email,
        action_requested="unblock_sender",
        action_performed="delete_sender_rule" if block.provider_rule_id else "none",
        operation_status="success",
        operation_detail=(f"Gmail filter {block.provider_rule_id} removed; " if block.provider_rule_id else "No filter existed (rule creation had failed); ")
                         + f"{block.sender_email} unblocked",
        blocked_sender_id=block.id,
    )
    return EnforcementActionResponse(id=block.id, status=block.status, provider_operation_status="success",
                                     message=f"Sender {block.sender_email} unblocked.")
