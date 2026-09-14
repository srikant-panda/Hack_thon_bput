"""ORG-4: management surface for org email notification groups.

Registered emails (grouped by role), per-event-type routing (min_role +
enabled), and the delivery log history. Emails/settings are analyst-readable
and admin-writable; viewers are blocked at the API and RLS layers.
"""

import logging
import re
from datetime import datetime

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.permissions import OrgRole, require_org_role
from app.core.security import CurrentUser, get_current_user
from app.db.models import Organization, OrgNotificationEmail, OrgNotificationLog
from app.db.session import get_db
from app.schemas.org_notifications import (
    NotificationEmailCreate,
    NotificationEmailResponse,
    NotificationEmailUpdate,
    NotificationLogResponse,
    NotificationSettingResponse,
    NotificationSettingUpdate,
)
from app.services.org_notification_service import (
    EVENT_TYPES,
    list_settings,
)

logger = logging.getLogger("cyberguard.org_notifications")

router = APIRouter(prefix="/org", tags=["Org Notifications"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


async def _get_email(db: AsyncSession, org_id: str, email_id: str) -> OrgNotificationEmail:
    row = await db.get(OrgNotificationEmail, email_id)
    if row is None or row.organization_id != org_id:
        raise NotFoundError("Notification email", email_id)
    return row


# ---------------------------------------------------------------------------
# Registered emails
# ---------------------------------------------------------------------------


@router.get("/{org_id}/notifications/emails", response_model=list[NotificationEmailResponse])
async def list_notification_emails(
    org_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(
        select(OrgNotificationEmail)
        .where(OrgNotificationEmail.organization_id == org_id)
        .order_by(OrgNotificationEmail.created_at.asc())
    )
    return [
        NotificationEmailResponse(
            id=e.id, email=e.email, role=e.role, is_enabled=e.is_enabled, created_at=e.created_at
        )
        for e in result.scalars().all()
    ]


@router.post("/{org_id}/notifications/emails", response_model=NotificationEmailResponse,
             status_code=status.HTTP_201_CREATED)
async def add_notification_email(
    org_id: str,
    payload: NotificationEmailCreate,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    if await db.get(Organization, org_id) is None:
        raise NotFoundError("Organization", org_id)
    email = payload.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise ValidationError("Invalid email address")
    existing = await db.execute(
        select(OrgNotificationEmail.id).where(
            OrgNotificationEmail.organization_id == org_id,
            OrgNotificationEmail.email == email,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"'{email}' is already registered for notifications")
    row = OrgNotificationEmail(organization_id=org_id, email=email, role=payload.role, created_by=user.id)
    db.add(row)
    await db.commit()
    return NotificationEmailResponse(id=row.id, email=row.email, role=row.role,
                                     is_enabled=row.is_enabled, created_at=row.created_at)


@router.put("/{org_id}/notifications/emails/{email_id}", response_model=NotificationEmailResponse)
async def update_notification_email(
    org_id: str,
    email_id: str,
    payload: NotificationEmailUpdate,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    row = await _get_email(db, org_id, email_id)
    if payload.role is not None:
        row.role = payload.role
    if payload.is_enabled is not None:
        row.is_enabled = payload.is_enabled
    await db.commit()
    return NotificationEmailResponse(id=row.id, email=row.email, role=row.role,
                                     is_enabled=row.is_enabled, created_at=row.created_at)


@router.delete("/{org_id}/notifications/emails/{email_id}")
async def delete_notification_email(
    org_id: str,
    email_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    row = await _get_email(db, org_id, email_id)
    await db.delete(row)
    await db.commit()
    return {"message": f"'{row.email}' removed from the notification list"}


# ---------------------------------------------------------------------------
# Event-type settings
# ---------------------------------------------------------------------------


@router.get("/{org_id}/notifications/settings", response_model=list[NotificationSettingResponse])
async def list_notification_settings(
    org_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    rows = await list_settings(db, org_id)
    await db.commit()  # persist any newly-seeded defaults
    return [
        NotificationSettingResponse(
            event_type=s.event_type, min_role=s.min_role,
            is_enabled=s.is_enabled, updated_at=s.updated_at,
        )
        for s in sorted(rows, key=lambda x: x.event_type)
    ]


@router.put("/{org_id}/notifications/settings/{event_type}", response_model=NotificationSettingResponse)
async def update_notification_setting(
    org_id: str,
    event_type: str,
    payload: NotificationSettingUpdate,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    if event_type not in EVENT_TYPES:
        raise ValidationError(f"Unknown event type: {event_type} (valid: {list(EVENT_TYPES)})")
    rows = {s.event_type: s for s in await list_settings(db, org_id)}
    setting = rows[event_type]
    if payload.min_role is not None:
        setting.min_role = payload.min_role
    if payload.is_enabled is not None:
        setting.is_enabled = payload.is_enabled
    setting.updated_by = user.id
    await db.commit()
    return NotificationSettingResponse(
        event_type=setting.event_type, min_role=setting.min_role,
        is_enabled=setting.is_enabled, updated_at=setting.updated_at,
    )


# ---------------------------------------------------------------------------
# Delivery log history
# ---------------------------------------------------------------------------


@router.get("/{org_id}/notifications/logs", response_model=list[NotificationLogResponse])
async def list_notification_logs(
    org_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None),
    log_status: str | None = Query(default=None, alias="status"),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    predicates = [OrgNotificationLog.organization_id == org_id]
    if event_type:
        predicates.append(OrgNotificationLog.event_type == event_type)
    if log_status:
        if log_status not in {"sent", "failed", "skipped"}:
            raise ValidationError("status must be sent | failed | skipped")
        predicates.append(OrgNotificationLog.status == log_status)
    for value, bound in ((from_date, lambda d: OrgNotificationLog.created_at >= d),
                         (to_date, lambda d: OrgNotificationLog.created_at <= d)):
        if value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValidationError("Invalid date filter (expected ISO-8601)") from exc
            predicates.append(bound(parsed))

    result = await db.execute(
        select(OrgNotificationLog)
        .where(*predicates)
        .order_by(OrgNotificationLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [
        NotificationLogResponse(
            id=log.id,
            event_type=log.event_type,
            recipients=log.recipients or [],
            subject=log.subject,
            event_metadata=log.event_metadata,
            status=log.status,
            error_detail=log.error_detail,
            created_at=log.created_at,
        )
        for log in result.scalars().all()
    ]
