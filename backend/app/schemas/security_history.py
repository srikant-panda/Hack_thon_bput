"""Schemas for security history and the flagged-email review view.

All responses are metadata-only: no tokens, no plaintext secrets, no chat
content.
"""

from typing import Any, Optional

from pydantic import BaseModel

EVENT_TYPES = [
    "scan_verdict", "quarantine", "release", "keep", "delete",
    "sender_block", "sender_release", "sender_expiry",
    "connector_connect", "connector_disconnect", "connector_test",
]
ACTOR_TYPES = ["user", "system", "scheduler"]


class SecurityEventRead(BaseModel):
    id: str
    event_type: str
    connector_id: Optional[str] = None
    provider: Optional[str] = None
    provider_message_id: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    explanation: Optional[str] = None
    indicators: list[dict[str, Any]] = []
    action_requested: Optional[str] = None
    action_performed: Optional[str] = None
    actor_type: str
    operation_status: Optional[str] = None
    operation_detail: Optional[str] = None
    quarantined_item_id: Optional[str] = None
    blocked_sender_id: Optional[str] = None
    created_at: Optional[str] = None


class SecurityHistoryListResponse(BaseModel):
    items: list[SecurityEventRead]
    total: int
    limit: int
    offset: int


class ReviewMessageMeta(BaseModel):
    provider_message_id: Optional[str] = None
    provider: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    body_preview: Optional[str] = None
    received_at: Optional[str] = None


class ReviewAvailableActions(BaseModel):
    release: bool
    keep: bool
    delete: bool
    delete_mode: Optional[str] = None  # "trash" | "permanent"
    connector_ready: bool


class QuarantineReviewResponse(BaseModel):
    item: dict[str, Any]
    message: ReviewMessageMeta
    scan_result: Optional[dict[str, Any]] = None
    event_chain: list[SecurityEventRead]
    available_actions: ReviewAvailableActions
