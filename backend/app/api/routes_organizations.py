"""Organization and Team Membership management endpoints."""

import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import (
    CurrentUser,
    TenantContext,
    get_current_user,
    get_tenant_context,
    require_org_enabled,
    require_role,
)
from app.db.models import Organization, OrganizationMember, User
from app.db.session import get_db
from app.schemas.organizations import (
    MemberAdd,
    MemberResponse,
    MemberRoleUpdate,
    OrganizationCreate,
    OrganizationResponse,
)

# Organization accounts are frozen until the Orgs Phase; every endpoint in
# this router answers 501 "coming soon" while ORG_ENABLED is false.
router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"],
    dependencies=[Depends(require_org_enabled())],
)


def _slugify(name: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", name).strip().lower()
    return re.sub(r"[-\s]+", "-", slug)


@router.get("", response_model=list[OrganizationResponse])
async def list_organizations(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List all organizations (including personal workspace) the current user belongs to."""
    query = (
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.organization))
        .where(OrganizationMember.user_id == user.id)
    )
    result = await db.execute(query)
    memberships = result.scalars().all()

    orgs = []
    for m in memberships:
        org = m.organization
        orgs.append(
            OrganizationResponse(
                id=org.id,
                name=org.name,
                slug=org.slug,
                is_personal=org.is_personal,
                owner_id=org.owner_id,
                created_at=org.created_at,
                role=m.role,
            )
        )
    return orgs


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create a new team organization (creator becomes owner and admin)."""
    base_slug = _slugify(payload.name) or "org"
    slug = f"{base_slug}-{str(uuid.uuid4())[:6]}"

    org = Organization(
        id=str(uuid.uuid4()),
        name=payload.name.strip(),
        slug=slug,
        is_personal=False,
        owner_id=user.id,
    )
    db.add(org)
    await db.flush()

    # Add creator as admin member
    member = OrganizationMember(
        id=str(uuid.uuid4()),
        organization_id=org.id,
        user_id=user.id,
        role="admin",
    )
    db.add(member)

    # Set as active organization for the user
    user_query = await db.execute(select(User).where(User.id == user.id))
    user_db = user_query.scalar_one()
    user_db.active_organization_id = org.id

    # Seed the default enforcement policy so server-mode integrations can
    # resolve a policy for this org immediately.
    from app.db.models import EnforcementPolicy

    db.add(EnforcementPolicy(
        organization_id=org.id,
        name="Balanced (default)",
        description="Auto-block critical/high, require approval for medium.",
        is_active=True,
    ))

    await db.commit()

    return OrganizationResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        is_personal=org.is_personal,
        owner_id=org.owner_id,
        created_at=org.created_at,
        role="admin",
    )


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Fetch details of an organization."""
    query = (
        select(Organization)
        .options(selectinload(Organization.members))
        .where(Organization.id == org_id)
    )
    result = await db.execute(query)
    org = result.scalar_one_or_none()
    if org is None:
        raise NotFoundError("Organization", org_id)

    # Check access
    member = next((m for m in org.members if m.user_id == user.id), None)
    if member is None and org.owner_id != user.id:
        raise PermissionDeniedError("You are not a member of this organization")

    role = member.role if member else "admin"
    return OrganizationResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        is_personal=org.is_personal,
        owner_id=org.owner_id,
        created_at=org.created_at,
        role=role,
    )


@router.get("/{org_id}/members", response_model=list[MemberResponse])
async def list_members(
    org_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List members and their roles in an organization."""
    # Ensure user has access to org
    org_query = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_query.scalar_one_or_none()
    if org is None:
        raise NotFoundError("Organization", org_id)

    members_query = (
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(OrganizationMember.organization_id == org_id)
    )
    result = await db.execute(members_query)
    members = result.scalars().all()

    # Verify caller is a member
    if not any(m.user_id == user.id for m in members) and org.owner_id != user.id:
        raise PermissionDeniedError("You are not a member of this organization")

    return [
        MemberResponse(
            id=m.id,
            organization_id=m.organization_id,
            user_id=m.user_id,
            email=m.user.email if m.user else None,
            full_name=m.user.full_name if m.user else None,
            role=m.role,
            joined_at=m.joined_at,
        )
        for m in members
    ]


@router.post("/{org_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
async def add_member(
    org_id: str,
    payload: MemberAdd,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Add or invite a user to an organization with a role (admin only)."""
    # Verify caller is admin
    caller_member_query = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user.id,
        )
    )
    caller_member = caller_member_query.scalar_one_or_none()
    org_query = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_query.scalar_one_or_none()
    if org is None:
        raise NotFoundError("Organization", org_id)

    if org.is_personal:
        raise ValidationError("Personal workspaces cannot have additional members. Create an organization instead.")

    if (caller_member is None or caller_member.role != "admin") and org.owner_id != user.id:
        raise PermissionDeniedError("Only organization admins can add members")

    # Find target user by email
    target_user_query = await db.execute(select(User).where(User.email == payload.email.strip().lower()))
    target_user = target_user_query.scalar_one_or_none()

    if target_user is None:
        # Pre-create user profile so they can join upon first login
        target_user = User(
            id=str(uuid.uuid4()),
            email=payload.email.strip().lower(),
            full_name=payload.email.split("@")[0],
            is_single_user=False,
        )
        db.add(target_user)
        await db.flush()

    # Check if already a member
    existing_query = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == target_user.id,
        )
    )
    if existing_query.scalar_one_or_none() is not None:
        raise ConflictError(f"User '{payload.email}' is already a member of this organization")

    new_member = OrganizationMember(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        user_id=target_user.id,
        role=payload.role,
    )
    db.add(new_member)
    await db.commit()

    return MemberResponse(
        id=new_member.id,
        organization_id=new_member.organization_id,
        user_id=new_member.user_id,
        email=target_user.email,
        full_name=target_user.full_name,
        role=new_member.role,
        joined_at=new_member.joined_at,
    )


@router.patch("/{org_id}/members/{target_user_id}", response_model=MemberResponse)
async def update_member_role(
    org_id: str,
    target_user_id: str,
    payload: MemberRoleUpdate,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Update a member's role (admin only)."""
    # Verify caller is admin
    caller_member_query = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user.id,
        )
    )
    caller_member = caller_member_query.scalar_one_or_none()
    org_query = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_query.scalar_one_or_none()
    if org is None:
        raise NotFoundError("Organization", org_id)

    if (caller_member is None or caller_member.role != "admin") and org.owner_id != user.id:
        raise PermissionDeniedError("Only organization admins can change member roles")

    # Fetch target membership
    member_query = (
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == target_user_id,
        )
    )
    result = await db.execute(member_query)
    target_member = result.scalar_one_or_none()
    if target_member is None:
        raise NotFoundError("Member in organization", target_user_id)

    target_member.role = payload.role
    await db.commit()

    return MemberResponse(
        id=target_member.id,
        organization_id=target_member.organization_id,
        user_id=target_member.user_id,
        email=target_member.user.email if target_member.user else None,
        full_name=target_member.user.full_name if target_member.user else None,
        role=target_member.role,
        joined_at=target_member.joined_at,
    )


@router.delete("/{org_id}/members/{target_user_id}")
async def remove_member(
    org_id: str,
    target_user_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Remove a member from an organization (admin only)."""
    # Verify caller is admin
    caller_member_query = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user.id,
        )
    )
    caller_member = caller_member_query.scalar_one_or_none()
    org_query = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_query.scalar_one_or_none()
    if org is None:
        raise NotFoundError("Organization", org_id)

    if (caller_member is None or caller_member.role != "admin") and org.owner_id != user.id:
        raise PermissionDeniedError("Only organization admins can remove members")

    if target_user_id == org.owner_id:
        raise ValidationError("Cannot remove the owner of the organization")

    member_query = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == target_user_id,
        )
    )
    target_member = member_query.scalar_one_or_none()
    if target_member is None:
        raise NotFoundError("Member in organization", target_user_id)

    await db.delete(target_member)
    await db.commit()

    return {"message": "Member removed successfully"}
