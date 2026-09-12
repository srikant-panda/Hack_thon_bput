"""Alert management endpoints using Async SQLAlchemy."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext, require_role
from app.db.session import get_db
from app.schemas.alerts import AlertListParams, AlertResponse, AlertStatusUpdate
from app.services import alert_service

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    params: Annotated[AlertListParams, Depends()],
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> Any:
    """List alerts scoped to the active organization with optional filters and search."""
    return await alert_service.list_alerts(
        db,
        tenant=tenant,
        severity=params.severity,
        module=params.module,
        status=params.status,
        search=params.search,
        offset=params.offset,
        limit=params.limit,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> Any:
    """Fetch a single alert with its recommended actions scoped to the active organization."""
    return await alert_service.get_alert(db, alert_id=alert_id, tenant=tenant)


@router.patch("/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Update an alert's status with audit logging (restricted to analysts and admins)."""
    return await alert_service.update_alert_status(
        db,
        alert_id=alert_id,
        tenant=tenant,
        new_status=payload.status,
        actor=tenant.user_email or tenant.user_id,
    )
