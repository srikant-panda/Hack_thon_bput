"""Organization-scoped Role-Based Access Control (ORG-1).

Roles (hierarchy: admin > analyst > viewer):

- ``admin``   — org creator / full management: members, API keys, settings.
- ``analyst`` — analysis access: read org data and settings, run scans.
- ``viewer``  — read-only, restricted from sensitive settings keys.

The dependency resolves the caller's membership in the org addressed by the
``org_id`` path parameter, so permissions are always evaluated against the
organization actually being touched (never against a client-claimed header).
"""

from enum import Enum

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import PermissionDeniedError
from app.core.security import CurrentUser, get_current_user
from app.db.models import Organization, OrganizationMember
from app.db.session import get_db


class OrgRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


ROLE_HIERARCHY: dict[OrgRole, int] = {
    OrgRole.VIEWER: 1,
    OrgRole.ANALYST: 2,
    OrgRole.ADMIN: 3,
}

# Settings keys a viewer must never read (blocked at the API layer and by the
# organization_settings RLS policy in migration 0008).
SENSITIVE_SETTING_KEYS = frozenset({"api_keys", "billing"})


def can_read_setting(role: str, key: str) -> bool:
    """Viewer restriction on sensitive setting keys (defense-in-depth twin of
    the RLS policy — also enforced where RLS does not apply, e.g. SQLite)."""
    if OrgRole(role) == OrgRole.VIEWER and key in SENSITIVE_SETTING_KEYS:
        return False
    return True


async def get_org_role(
    org_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OrganizationMember:
    """Resolve the caller's membership in the org named by the ``org_id`` path
    parameter. The org creator counts as admin even without a membership row
    (legacy personal/seeded orgs)."""
    result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user.id,
        )
    )
    member = result.scalar_one_or_none()
    if member is not None:
        return member

    org = await db.get(Organization, org_id)
    if org is not None and org.owner_id == user.id:
        # Synthetic membership: NOT added to the session, never persisted.
        return OrganizationMember(
            organization_id=org_id,
            user_id=user.id,
            role=OrgRole.ADMIN.value,
        )
    raise PermissionDeniedError("You are not a member of this organization")


def require_org_role(minimum: OrgRole):
    """Dependency factory: require at least ``minimum`` in the path org.

    Usage:
        member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN))
    """

    async def _checker(
        member: OrganizationMember = Depends(get_org_role),
    ) -> OrganizationMember:
        actual = ROLE_HIERARCHY[OrgRole(member.role)]
        required = ROLE_HIERARCHY[minimum]
        if actual < required:
            raise PermissionDeniedError(
                f"Insufficient permissions (requires {minimum.value})"
            )
        return member

    return _checker
