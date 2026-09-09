"""Pydantic schemas for multi-tenant organizations and memberships."""

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

RoleValue = Literal["admin", "analyst", "viewer"]


class OrganizationCreate(BaseModel):
    """Payload to create a new organization."""

    name: str = Field(min_length=1, max_length=100)


class OrganizationResponse(BaseModel):
    """Organization details."""

    id: str
    name: str
    slug: str
    is_personal: bool
    owner_id: str
    created_at: Optional[Any] = None
    role: Optional[str] = None

    model_config = {"from_attributes": True}


class MemberAdd(BaseModel):
    """Payload to add a user to an organization."""

    email: str = Field(min_length=3)
    role: RoleValue = "analyst"


class MemberRoleUpdate(BaseModel):
    """Payload to change a member's role."""

    role: RoleValue


class MemberResponse(BaseModel):
    """Organization membership information."""

    id: str
    organization_id: str
    user_id: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str
    joined_at: Optional[Any] = None

    model_config = {"from_attributes": True}
