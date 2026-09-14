"""Pydantic schemas for ORG-3: org mail server connectors."""

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

ProviderType = Literal["google_workspace", "microsoft_365", "imap_smtp"]
MailLogType = Literal["connection", "scan", "quarantine", "error"]


class CreateMailServerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    provider_type: ProviderType
    credentials: Optional[dict[str, Any]] = None  # encrypted at rest if given
    connect_now: bool = True


class ConnectMailServerRequest(BaseModel):
    """Reconnect (stored credentials) or rotate credentials while connecting."""

    credentials: Optional[dict[str, Any]] = None


class MailServerResponse(BaseModel):
    """Server-management view — NEVER carries credential material."""

    id: str
    name: str
    provider_type: str
    status: str
    last_connected_at: Optional[Any] = None
    last_error: Optional[str] = None
    has_credentials: bool = False
    created_at: Optional[Any] = None


class MailServerLogResponse(BaseModel):
    id: str
    mail_server_id: str
    log_type: str
    message: str
    metadata: Optional[dict[str, Any]] = None
    created_at: Optional[Any] = None


class MailServerSettingsResponse(BaseModel):
    mail_server_id: str
    settings: dict[str, Any]


class MailServerSettingsUpdate(BaseModel):
    settings: dict[str, Any]


class MailServerActionResponse(BaseModel):
    id: str
    status: str
    detail: dict[str, Any] = {}


class FetchEmailsResponse(BaseModel):
    mail_server_id: str
    count: int
    messages: list[dict[str, Any]]
