"""Pydantic schemas for ORG-4: org notification groups."""

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, EmailStr  # noqa: F401 - EmailStr needs email-validator

RoleGroup = Literal["admin", "analyst", "viewer"]


class NotificationEmailCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    role: RoleGroup = "analyst"


class NotificationEmailUpdate(BaseModel):
    role: Optional[RoleGroup] = None
    is_enabled: Optional[bool] = None


class NotificationEmailResponse(BaseModel):
    id: str
    email: str
    role: str
    is_enabled: bool
    created_at: Optional[Any] = None


class NotificationSettingResponse(BaseModel):
    event_type: str
    min_role: str
    is_enabled: bool
    updated_at: Optional[Any] = None


class NotificationSettingUpdate(BaseModel):
    min_role: Optional[RoleGroup] = None
    is_enabled: Optional[bool] = None


class NotificationLogResponse(BaseModel):
    id: str
    event_type: str
    recipients: list[dict[str, Any]] = []
    subject: str
    event_metadata: Optional[dict[str, Any]] = None
    status: str
    error_detail: Optional[str] = None
    created_at: Optional[Any] = None
