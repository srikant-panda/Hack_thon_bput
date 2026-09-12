"""Response execution service using Async SQLAlchemy."""

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, PermissionDeniedError
from app.core.security import TenantContext, tenant_criteria
from app.db.models import ResponseCatalog, ResponseExecution
from app.services import audit_service

logger = logging.getLogger("cyberguard.response")


async def get_response_catalog(db: AsyncSession) -> list[ResponseCatalog]:
    """Fetch the full response action catalog."""
    result = await db.execute(select(ResponseCatalog).order_by(ResponseCatalog.action))
    return list(result.scalars().all())


async def execute_response(
    db: AsyncSession,
    *,
    tenant: TenantContext,
    catalog_id: str,
    target: Optional[str],
    approved: bool,
    executed_by: str,
    user_role: str = "analyst",
) -> ResponseExecution:
    """Execute a response action with human approval check and audit logging."""
    catalog_query = await db.execute(select(ResponseCatalog).where(ResponseCatalog.id == catalog_id))
    catalog = catalog_query.scalar_one_or_none()
    if catalog is None:
        raise NotFoundError("Response catalog action", catalog_id)

    # Check approval gate
    if catalog.requires_approval and not approved:
        raise PermissionDeniedError("This action requires explicit approval")

    execution_status = "executed"

    execution = ResponseExecution(
        id=str(uuid.uuid4()),
        organization_id=tenant.organization_id,
        owner_user_id=tenant.owner_user_id,
        catalog_id=catalog.id,
        action_name=catalog.action,
        target=target,
        status=execution_status,
        executed_by=executed_by,
        approved_by=executed_by if approved else None,
    )
    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    await audit_service.log_action(
        db,
        tenant=tenant,
        user_id=executed_by,
        user_name=executed_by,
        action=f"Response executed: {catalog.action}",
        resource=f"execution:{execution.id}",
        details=f"Target: {target}; Status: {execution_status}; Approved: {approved}",
    )

    return execution


async def get_execution_history(
    db: AsyncSession,
    tenant: TenantContext,
    limit: int = 50,
) -> list[ResponseExecution]:
    """Fetch recent response executions scoped to the active tenant."""
    query = (
        select(ResponseExecution)
        .where(tenant_criteria(ResponseExecution, tenant))
        .order_by(desc(ResponseExecution.created_at))
        .limit(limit)
    )
    result = await db.execute(query)
    return list(result.scalars().all())
