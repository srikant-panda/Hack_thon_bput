"""Action execution management — approval workflow, quarantine, block lists.

Control plane for ActionExecution records created by the dual-mode enforcement
pipeline (Phase 2): SOC analysts list/filter executions, approve or reject
pending actions, release quarantined items, and manage block lists. Every
state change is written to the audit log.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext, require_role
from app.db.models import ActionExecution, Alert
from app.db.session import get_db
from app.services.action_executor import action_executor
from app.services.audit_service import log_action

logger = logging.getLogger("cyberguard.actions")

router = APIRouter(prefix="/actions", tags=["Actions"])

QUARANTINE_ACTION_TYPES = ("quarantine_email", "block_and_quarantine", "flag_for_review")
BLOCK_ACTION_TYPES = ("block_url", "block_ip", "drop_packet")


# --- Schemas ---

class ApprovalRequest(BaseModel):
    """Request to approve a pending action."""
    comment: Optional[str] = Field(default=None, max_length=500)


class RejectionRequest(BaseModel):
    """Request to reject a pending action."""
    reason: str = Field(..., min_length=1, max_length=500)


class ActionExecutionResponse(BaseModel):
    """Response schema for action execution records."""
    id: str
    organization_id: Optional[str]
    alert_id: Optional[str]
    event_id: Optional[str]
    action_type: str
    target: dict[str, Any]
    status: str
    execution_mode: str
    triggered_by: str
    requires_approval: bool
    approved_by: Optional[str]
    approved_at: Optional[str]
    rejection_reason: Optional[str]
    executed_at: Optional[str]
    execution_result: Optional[dict[str, Any]]
    risk_score: int
    severity: str
    threat_type: str
    module: str
    policy_id: Optional[str]
    created_at: str


class ActionListResponse(BaseModel):
    """Paginated list of action executions."""
    total: int
    page: int
    page_size: int
    items: list[ActionExecutionResponse]


# --- Action listing & inspection ---


@router.get("", response_model=ActionListResponse)
async def list_actions(
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    action_type: Optional[str] = Query(default=None),
    module: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> ActionListResponse:
    """List action executions with filtering.

    Query params:
    - status: pending | success | rejected | skipped | released | unblocked
    - action_type: quarantine_email | block_url | drop_packet | etc.
    - module: phishing | url | network | account_takeover | deepfake
    - severity: critical | high | medium | low
    - page, page_size: pagination
    """
    query = select(ActionExecution).where(
        ActionExecution.organization_id == tenant.organization_id
    )

    if status_filter:
        query = query.where(ActionExecution.status == status_filter)
    if action_type:
        query = query.where(ActionExecution.action_type == action_type)
    if module:
        query = query.where(ActionExecution.module == module)
    if severity:
        query = query.where(ActionExecution.severity == severity)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(ActionExecution.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    actions = result.scalars().all()

    return ActionListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[_to_response(a) for a in actions],
    )


@router.get("/quarantine/list", response_model=ActionListResponse)
async def list_quarantine(
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> ActionListResponse:
    """List all currently quarantined items (emails, media, URLs)."""
    query = select(ActionExecution).where(
        ActionExecution.organization_id == tenant.organization_id,
        ActionExecution.action_type.in_(QUARANTINE_ACTION_TYPES),
        ActionExecution.status == "success",
    )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(ActionExecution.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    actions = result.scalars().all()

    return ActionListResponse(
        total=total, page=page, page_size=page_size,
        items=[_to_response(a) for a in actions],
    )


@router.get("/blocklist/list", response_model=ActionListResponse)
async def list_blocklist(
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> ActionListResponse:
    """List all currently blocked items (URLs, IPs)."""
    query = select(ActionExecution).where(
        ActionExecution.organization_id == tenant.organization_id,
        ActionExecution.action_type.in_(BLOCK_ACTION_TYPES),
        ActionExecution.status == "success",
    )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(ActionExecution.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    actions = result.scalars().all()

    return ActionListResponse(
        total=total, page=page, page_size=page_size,
        items=[_to_response(a) for a in actions],
    )


@router.get("/{action_id}", response_model=ActionExecutionResponse)
async def get_action(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> ActionExecutionResponse:
    """Get a single action execution by ID."""
    action = await _get_action_or_404(db, action_id, tenant.organization_id)
    return _to_response(action)


# --- Approval workflow ---


@router.post("/{action_id}/approve", response_model=ActionExecutionResponse)
async def approve_action(
    action_id: str,
    request: ApprovalRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> ActionExecutionResponse:
    """Approve a pending action; the enforcement action executes immediately."""
    action = await _get_action_or_404(db, action_id, tenant.organization_id)

    if action.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action is not pending (current status: {action.status})",
        )

    if not action.requires_approval:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action does not require approval",
        )

    alert = await _load_alert(db, action)
    execution_result = await action_executor.execute_simulated(action.action_type, alert)

    now = datetime.now(timezone.utc)
    action.status = "success"
    action.approved_by = tenant.user_id
    action.approved_at = now
    action.executed_at = now
    action.execution_result = execution_result

    await db.commit()
    await db.refresh(action)

    await log_action(
        db,
        organization_id=tenant.organization_id,
        user_id=tenant.user_id,
        user_name=tenant.user_email,
        action="approve_action_execution",
        resource=f"action_execution:{action_id}",
        details=request.comment or f"Approved '{action.action_type}' (alert {action.alert_id})",
    )

    logger.info("Action %s approved by %s and executed successfully", action_id, tenant.user_id)
    return _to_response(action)


@router.post("/{action_id}/reject", response_model=ActionExecutionResponse)
async def reject_action(
    action_id: str,
    request: RejectionRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> ActionExecutionResponse:
    """Reject a pending action; the enforcement action is never executed."""
    action = await _get_action_or_404(db, action_id, tenant.organization_id)

    if action.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action is not pending (current status: {action.status})",
        )

    action.status = "rejected"
    action.rejection_reason = request.reason
    action.approved_by = tenant.user_id  # reviewer identity for both outcomes
    action.approved_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(action)

    await log_action(
        db,
        organization_id=tenant.organization_id,
        user_id=tenant.user_id,
        user_name=tenant.user_email,
        action="reject_action_execution",
        resource=f"action_execution:{action_id}",
        details=f"Rejected '{action.action_type}': {request.reason}",
    )

    logger.info("Action %s rejected by %s: %s", action_id, tenant.user_id, request.reason)
    return _to_response(action)


# --- Quarantine & block-list lifecycle ---


@router.post("/quarantine/{action_id}/release", response_model=ActionExecutionResponse)
async def release_quarantine(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> ActionExecutionResponse:
    """Release a quarantined item (e.g. a false positive) back to the user."""
    action = await _get_action_or_404(db, action_id, tenant.organization_id)

    if action.action_type not in QUARANTINE_ACTION_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action type '{action.action_type}' is not a quarantine action",
        )
    if action.status != "success":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot release action with status '{action.status}'",
        )

    action.status = "released"
    action.execution_result = {
        **(action.execution_result or {}),
        "released_by": tenant.user_id,
        "released_at": datetime.now(timezone.utc).isoformat(),
    }

    await db.commit()
    await db.refresh(action)

    await log_action(
        db,
        organization_id=tenant.organization_id,
        user_id=tenant.user_id,
        user_name=tenant.user_email,
        action="release_quarantine",
        resource=f"action_execution:{action_id}",
        details=f"Released quarantined item (target: {action.target})",
    )

    logger.info("Quarantine %s released by %s", action_id, tenant.user_id)
    return _to_response(action)


@router.post("/blocklist/{action_id}/unblock", response_model=ActionExecutionResponse)
async def unblock_item(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> ActionExecutionResponse:
    """Remove a previously blocked URL/IP from the block list."""
    action = await _get_action_or_404(db, action_id, tenant.organization_id)

    if action.action_type not in BLOCK_ACTION_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action type '{action.action_type}' is not a block action",
        )
    if action.status != "success":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot unblock action with status '{action.status}'",
        )

    action.status = "unblocked"
    action.execution_result = {
        **(action.execution_result or {}),
        "unblocked_by": tenant.user_id,
        "unblocked_at": datetime.now(timezone.utc).isoformat(),
    }

    await db.commit()
    await db.refresh(action)

    await log_action(
        db,
        organization_id=tenant.organization_id,
        user_id=tenant.user_id,
        user_name=tenant.user_email,
        action="unblock_item",
        resource=f"action_execution:{action_id}",
        details=f"Unblocked item (target: {action.target})",
    )

    logger.info("Block %s removed by %s", action_id, tenant.user_id)
    return _to_response(action)


# --- Helpers ---


async def _get_action_or_404(
    db: AsyncSession, action_id: str, organization_id: str
) -> ActionExecution:
    """Fetch an action execution or raise 404 (org-scoped)."""
    result = await db.execute(
        select(ActionExecution).where(
            ActionExecution.id == action_id,
            ActionExecution.organization_id == organization_id,
        )
    )
    action = result.scalars().first()
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action execution '{action_id}' not found",
        )
    return action


async def _load_alert(db: AsyncSession, action: ActionExecution) -> Alert:
    """Load the alert referenced by an execution (explicit select — lazy
    relationship access is not available on async sessions)."""
    result = await db.execute(select(Alert).where(Alert.id == action.alert_id))
    alert = result.scalars().first()
    if alert is None:
        # Fallback for executions whose alert row vanished (SET NULL cascade):
        # simulate against a detached shell so the payload is still accurate.
        return Alert(
            id=action.alert_id or action.id,
            module=action.module,
            severity=action.severity,
            risk_score=action.risk_score,
        )
    return alert


def _to_response(action: ActionExecution) -> ActionExecutionResponse:
    """Convert ORM model to response schema."""
    return ActionExecutionResponse(
        id=action.id,
        organization_id=action.organization_id,
        alert_id=action.alert_id,
        event_id=action.event_id,
        action_type=action.action_type,
        target=action.target or {},
        status=action.status,
        execution_mode=action.execution_mode,
        triggered_by=action.triggered_by,
        requires_approval=action.requires_approval,
        approved_by=action.approved_by,
        approved_at=action.approved_at.isoformat() if action.approved_at else None,
        rejection_reason=action.rejection_reason,
        executed_at=action.executed_at.isoformat() if action.executed_at else None,
        execution_result=action.execution_result,
        risk_score=action.risk_score,
        severity=action.severity,
        threat_type=action.threat_type,
        module=action.module,
        policy_id=action.policy_id,
        created_at=action.created_at.isoformat() if action.created_at else None,
    )
