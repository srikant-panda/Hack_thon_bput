"""Pydantic schemas for multi-tenant organizations and memberships."""

from datetime import datetime
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
    display_name: Optional[str] = None
    slug: str
    is_personal: bool
    owner_id: str
    status: Optional[str] = None
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


# ---------------------------------------------------------------------------
# ORG-1: API keys and org settings
# ---------------------------------------------------------------------------

class ApiKeyCreate(BaseModel):
    """Payload to create an org API key."""

    name: str = Field(min_length=1, max_length=120)
    expires_at: Optional[datetime] = None  # null = never expires


class ApiKeyResponse(BaseModel):
    """API key as listed in settings — never contains the hash or plaintext."""

    id: str
    name: str
    key_prefix: str
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    status: str
    created_at: Optional[Any] = None

    model_config = {"from_attributes": True}


class ApiKeyCreatedResponse(ApiKeyResponse):
    """Create response — carries the plaintext key EXACTLY ONCE."""

    key: str


class SettingUpsert(BaseModel):
    """Payload to write one org setting (key comes from the path)."""

    value: dict[str, Any]


class SettingResponse(BaseModel):
    key: str
    value: dict[str, Any]
    updated_at: Optional[Any] = None

    model_config = {"from_attributes": True}
