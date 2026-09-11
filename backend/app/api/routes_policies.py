"""Enforcement policy management — CRUD for org admins.

Read access for all SOC roles; mutations (update/activate) are admin-only.
Only one policy per organization may be active at a time; the integration
surface (Phase 2) resolves the active policy for enforcement decisions.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext, require_role
from app.db.models import EnforcementPolicy
from app.db.session import get_db
from app.services.audit_service import log_action

logger = logging.getLogger("cyberguard.policies")

router = APIRouter(prefix="/policies", tags=["Policies"])

# Actions the policy engine / executor understands. Generic policy verbs are
# refined per module by the executor (refine_action_for_module).
ALLOWED_ACTIONS = frozenset({
    "allow", "warn_and_log", "tag_and_warn", "flag_for_review",
    "rate_limit", "require_mfa", "revoke_session",
    "block", "block_and_quarantine",
})


# --- Schemas ---

class PolicyResponse(BaseModel):
    """Response schema for enforcement policy."""
    id: str
    organization_id: str
    name: str
    description: Optional[str]
    is_active: bool

    # Thresholds
    phishing_high_threshold: int
    phishing_medium_threshold: int
    deepfake_high_threshold: int
    deepfake_medium_threshold: int
    ato_high_threshold: int
    ato_medium_threshold: int
    network_high_threshold: int
    network_medium_threshold: int
    impersonation_high_threshold: int
    impersonation_medium_threshold: int

    # Actions
    action_on_critical: str
    action_on_high: str
    action_on_medium: str
    action_on_low: str

    # Auto-execute
    auto_execute_critical: bool
    auto_execute_high: bool
    auto_execute_medium: bool
    auto_execute_low: bool

    # Notifications
    notify_soc_on_critical: bool
    notify_soc_on_high: bool
    notify_user_on_medium: bool

    created_at: str
    updated_at: str


class PolicyUpdateRequest(BaseModel):
    """Request to update an enforcement policy."""
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None

    # Thresholds (all optional — only update what's provided)
    phishing_high_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    phishing_medium_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    deepfake_high_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    deepfake_medium_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    ato_high_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    ato_medium_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    network_high_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    network_medium_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    impersonation_high_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    impersonation_medium_threshold: Optional[int] = Field(default=None, ge=0, le=100)

    # Actions
    action_on_critical: Optional[str] = None
    action_on_high: Optional[str] = None
    action_on_medium: Optional[str] = None
    action_on_low: Optional[str] = None

    # Auto-execute
    auto_execute_critical: Optional[bool] = None
    auto_execute_high: Optional[bool] = None
    auto_execute_medium: Optional[bool] = None
    auto_execute_low: Optional[bool] = None

    # Notifications
    notify_soc_on_critical: Optional[bool] = None
    notify_soc_on_high: Optional[bool] = None
    notify_user_on_medium: Optional[bool] = None


class PolicyListResponse(BaseModel):
    """List of policies for an organization."""
    policies: list[PolicyResponse]
    active_policy_id: Optional[str]


# --- Endpoints ---


@router.get("", response_model=PolicyListResponse)
async def list_policies(
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> PolicyListResponse:
    """List all enforcement policies for the organization."""
    result = await db.execute(
        select(EnforcementPolicy).where(
            EnforcementPolicy.organization_id == tenant.organization_id
        )
    )
    policies = result.scalars().all()

    active = next((p for p in policies if p.is_active), None)

    return PolicyListResponse(
        policies=[_to_response(p) for p in policies],
        active_policy_id=active.id if active else None,
    )


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> PolicyResponse:
    """Get a single enforcement policy."""
    policy = await _get_policy_or_404(db, policy_id, tenant.organization_id)
    return _to_response(policy)


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: str,
    request: PolicyUpdateRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin"])),
) -> PolicyResponse:
    """Update an enforcement policy (org admins only)."""
    policy = await _get_policy_or_404(db, policy_id, tenant.organization_id)

    update_data = request.model_dump(exclude_unset=True)

    for field in ("action_on_critical", "action_on_high", "action_on_medium", "action_on_low"):
        value = update_data.get(field)
        if value is not None and value not in ALLOWED_ACTIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid action '{value}' for {field}. "
                       f"Allowed: {', '.join(sorted(ALLOWED_ACTIONS))}",
            )

    for field, value in update_data.items():
        if hasattr(policy, field):
            setattr(policy, field, value)

    await db.commit()
    await db.refresh(policy)

    await log_action(
        db,
        organization_id=tenant.organization_id,
        user_id=tenant.user_id,
        user_name=tenant.user_email,
        action="update_enforcement_policy",
        resource=f"enforcement_policy:{policy_id}",
        details=f"Updated fields: {', '.join(sorted(update_data.keys()))}",
    )

    logger.info("Policy %s updated by %s: %s", policy_id, tenant.user_id, list(update_data.keys()))
    return _to_response(policy)


@router.post("/{policy_id}/activate", response_model=PolicyResponse)
async def activate_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin"])),
) -> PolicyResponse:
    """Activate a policy (deactivates all others for the org).

    Only one policy can be active per organization at a time."""
    policy = await _get_policy_or_404(db, policy_id, tenant.organization_id)

    result = await db.execute(
        select(EnforcementPolicy).where(
            EnforcementPolicy.organization_id == tenant.organization_id,
            EnforcementPolicy.id != policy_id,
        )
    )
    for other in result.scalars().all():
        other.is_active = False

    policy.is_active = True

    await db.commit()
    await db.refresh(policy)

    await log_action(
        db,
        organization_id=tenant.organization_id,
        user_id=tenant.user_id,
        user_name=tenant.user_email,
        action="activate_enforcement_policy",
        resource=f"enforcement_policy:{policy_id}",
        details=f"Policy '{policy.name}' is now active",
    )

    logger.info("Policy %s activated by %s", policy_id, tenant.user_id)
    return _to_response(policy)


# --- Helpers ---


async def _get_policy_or_404(
    db: AsyncSession, policy_id: str, organization_id: str
) -> EnforcementPolicy:
    result = await db.execute(
        select(EnforcementPolicy).where(
            EnforcementPolicy.id == policy_id,
            EnforcementPolicy.organization_id == organization_id,
        )
    )
    policy = result.scalars().first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found",
        )
    return policy


def _to_response(policy: EnforcementPolicy) -> PolicyResponse:
    return PolicyResponse(
        id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        is_active=policy.is_active,
        phishing_high_threshold=policy.phishing_high_threshold,
        phishing_medium_threshold=policy.phishing_medium_threshold,
        deepfake_high_threshold=policy.deepfake_high_threshold,
        deepfake_medium_threshold=policy.deepfake_medium_threshold,
        ato_high_threshold=policy.ato_high_threshold,
        ato_medium_threshold=policy.ato_medium_threshold,
        network_high_threshold=policy.network_high_threshold,
        network_medium_threshold=policy.network_medium_threshold,
        impersonation_high_threshold=policy.impersonation_high_threshold,
        impersonation_medium_threshold=policy.impersonation_medium_threshold,
        action_on_critical=policy.action_on_critical,
        action_on_high=policy.action_on_high,
        action_on_medium=policy.action_on_medium,
        action_on_low=policy.action_on_low,
        auto_execute_critical=policy.auto_execute_critical,
        auto_execute_high=policy.auto_execute_high,
        auto_execute_medium=policy.auto_execute_medium,
        auto_execute_low=policy.auto_execute_low,
        notify_soc_on_critical=policy.notify_soc_on_critical,
        notify_soc_on_high=policy.notify_soc_on_high,
        notify_user_on_medium=policy.notify_user_on_medium,
        created_at=policy.created_at.isoformat() if policy.created_at else None,
        updated_at=policy.updated_at.isoformat() if policy.updated_at else None,
    )
