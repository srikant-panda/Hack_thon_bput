"""Audit logging service using Async SQLAlchemy."""

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog

logger = logging.getLogger("cyberguard.audit")


async def log_action(
    db: AsyncSession,
    *,
    organization_id: Optional[str] = None,
    user_id: Optional[str] = None,
    user_name: Optional[str] = None,
    action: str,
    resource: Optional[str] = None,
    details: Optional[str] = None,
) -> None:
    """Insert an audit log entry for a state-changing operation."""
    try:
        entry = AuditLog(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            user_id=user_id,
            user_name=user_name or "System",
            action=action,
            resource=resource,
            details=details,
        )
        db.add(entry)
        await db.commit()
    except Exception:
        logger.exception("Failed to write audit log for action %r", action)


async def get_audit_logs(
    db: AsyncSession,
    organization_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLog]:
    """Fetch audit logs scoped to the active organization, newest first."""
    query = (
        select(AuditLog)
        .where(AuditLog.organization_id == organization_id)
        .order_by(desc(AuditLog.created_at))
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(query)
    return list(result.scalars().all())
