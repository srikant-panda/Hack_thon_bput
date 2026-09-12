"""Common internal email model.

Provider adapters (Gmail today, Outlook later) map their native API payloads
onto this schema so detection engines never see provider-specific formats.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class NormalizedMessage(BaseModel):
    provider_message_id: str
    provider: str = "gmail"
    sender: str
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)
    # filename / size / mime_type metadata only — no binary content yet.
    attachments_meta: list[dict] = Field(default_factory=list)
    received_at: Optional[datetime] = None
    is_read: bool = True


class MessageSummary(BaseModel):
    """Metadata view for mailbox listings (bodies truncated or omitted)."""

    provider_message_id: str
    provider: str = "gmail"
    sender: str
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    received_at: Optional[datetime] = None
    is_read: bool = True
    has_attachments: bool = False
    body_preview: str = ""
