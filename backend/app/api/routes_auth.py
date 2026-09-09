"""Authentication context and current user endpoints."""

from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import NotFoundError, PermissionDeniedError
from app.core.security import CurrentUser, TenantContext, get_current_user, get_tenant_context
from app.db.models import Organization, OrganizationMember, User
from app.db.session import get_db

router = APIRouter(prefix="/auth", tags=["Auth"])


class SwitchOrgRequest(BaseModel):
    organization_id: str


@router.get("/me")
async def read_current_user(
    user: CurrentUser = Depends(get_current_user),
    tenant: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return profile details, active workspace, and organization memberships."""
    # Query user with memberships
    query = (
        select(User)
        .options(selectinload(User.memberships).selectinload(OrganizationMember.organization))
        .where(User.id == user.id)
    )
    res = await db.execute(query)
    user_db = res.scalar_one()

    orgs_list = []
    personal_org_id = None
    for m in user_db.memberships:
        org = m.organization
        if org.is_personal:
            personal_org_id = org.id
        orgs_list.append(
            {
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "is_personal": org.is_personal,
                "role": m.role,
            }
        )

    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_single_user": tenant.is_single_user,
        "active_role": tenant.role,
        "active_organization": {
            "id": tenant.organization_id,
            "name": tenant.organization_name,
            "is_personal": tenant.is_single_user,
            "role": tenant.role,
        },
        "personal_organization_id": personal_org_id,
        "organizations": orgs_list,
    }


@router.post("/switch-org")
async def switch_organization(
    payload: SwitchOrgRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Switch user's default active organization."""
    # Verify user is a member of the target organization
    member_query = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == payload.organization_id,
            OrganizationMember.user_id == user.id,
        )
    )
    membership = member_query.scalar_one_or_none()
    if membership is None:
        # Check if owner
        org_query = await db.execute(select(Organization).where(Organization.id == payload.organization_id))
        org = org_query.scalar_one_or_none()
        if org is None or org.owner_id != user.id:
            raise PermissionDeniedError("You are not a member of this organization")

    user_query = await db.execute(select(User).where(User.id == user.id))
    user_db = user_query.scalar_one()
    user_db.active_organization_id = payload.organization_id
    await db.commit()

    return {"message": "Active organization updated", "active_organization_id": payload.organization_id}