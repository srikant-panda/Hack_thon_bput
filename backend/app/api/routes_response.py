"""Response action endpoints using Async SQLAlchemy."""

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext, require_role
from app.db.session import get_db
from app.schemas.responses import ResponseExecuteRequest, ResponseExecutionResponse
from app.services import response_service

router = APIRouter(prefix="/responses", tags=["Response Actions"])


@router.get("/catalog")
async def get_response_catalog(
    db: AsyncSession = Depends(get_db),
    _tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> list[dict[str, Any]]:
    """Return the full response action catalog."""
    actions = await response_service.get_response_catalog(db)
    return [
        {
            "id": act.id,
            "action": act.action,
            "target_type": act.target_type,
            "automation_level": act.automation_level,
            "requires_approval": act.requires_approval,
            "description": act.description,
        }
        for act in actions
    ]


@router.post("/execute", response_model=ResponseExecutionResponse)
async def execute_response(
    payload: ResponseExecuteRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Execute (or approve) a catalog response action against a target."""
    return await response_service.execute_response(
        db,
        organization_id=tenant.organization_id,
        catalog_id=payload.catalog_id,
        target=payload.target,
        approved=payload.approved,
        executed_by=tenant.user_email or tenant.user_id,
        user_role=tenant.role,
    )


@router.get("/history", response_model=list[ResponseExecutionResponse])
async def get_execution_history(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> Any:
    """Return recent response executions scoped to the active organization, newest first."""
    return await response_service.get_execution_history(
        db, organization_id=tenant.organization_id, limit=limit
    )
