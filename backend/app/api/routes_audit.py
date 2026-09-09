"""Audit log endpoints using Async SQLAlchemy."""

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext, require_role
from app.db.session import get_db
from app.services import audit_service

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get("")
async def get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> list[dict[str, Any]]:
    """Return recent audit log entries scoped to the active organization, newest first."""
    logs = await audit_service.get_audit_logs(
        db, organization_id=tenant.organization_id, limit=limit, offset=offset
    )
    return [
        {
            "id": log.id,
            "organization_id": log.organization_id,
            "user_id": log.user_id,
            "user_name": log.user_name,
            "action": log.action,
            "resource": log.resource,
            "details": log.details,
            "created_at": log.created_at,
        }
        for log in logs
    ]
