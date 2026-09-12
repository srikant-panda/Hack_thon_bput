"""Dashboard summary endpoints using Async SQLAlchemy."""

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext, require_role
from app.db.session import get_db
from app.services import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> dict[str, Any]:
    """Return aggregated metrics, attack timeline, and top targets for the active organization."""
    return await dashboard_service.get_dashboard_summary(
        db, tenant=tenant
    )
