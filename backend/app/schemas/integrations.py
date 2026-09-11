"""Request/response schemas for server-mode integration endpoints."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# --- Base request with mode support ---

class IntegrationBaseRequest(BaseModel):
    """Base schema for all integration requests."""
    mode: str = Field(default="server", description="Operation mode ('server' for integrations; 'client' records recommendation only)")
    enforcement_policy: Optional[str] = Field(
        default=None,
        description="Policy level: 'strict', 'balanced', 'permissive' (optional, uses org default if not specified)",
    )
    auto_execute: bool = Field(
        default=True,
        description="Auto-execute enforcement actions without approval",
    )


# --- Email Gateway ---

class EmailGatewayAnalyzeRequest(IntegrationBaseRequest):
    """Request to analyze an email via the email gateway integration."""
    sender: str = Field(..., min_length=1)
    recipient: str = Field(..., min_length=1)
    subject: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)
    headers: Optional[dict[str, Any]] = None
    attachments: Optional[list[dict[str, Any]]] = None
    email_id: Optional[str] = None  # External email ID from the gateway


class IntegrationDecisionResponse(BaseModel):
    """Standard response for all integration endpoints."""
    decision: str  # QUARANTINE_EMAIL | BLOCK_URL | ALLOW | TAG_AND_WARN | RATE_LIMIT | ...
    alert_id: str
    risk_score: int
    severity: str  # critical | high | medium | low | safe (display severity)
    threat_type: Optional[str]
    explanation: Optional[str]
    mitre_techniques: Optional[list[dict[str, Any]]]  # [{id, name}, ...] mirroring Alert.mitre

    # Execution details
    action_executed: bool
    execution_id: Optional[str]  # ActionExecution.id
    execution_status: str  # success | pending | skipped
    quarantine_id: Optional[str]  # If quarantined
    block_id: Optional[str]  # If blocked
    requires_approval: bool
    approval_url: Optional[str]  # URL to approve/reject in dashboard

    # Metadata
    policy_id: Optional[str]
    timestamp: str


# --- URL Proxy ---

class UrlProxyAnalyzeRequest(IntegrationBaseRequest):
    """Request to analyze a URL via the web proxy integration."""
    url: str = Field(..., min_length=1)
    user_agent: Optional[str] = None
    source_ip: Optional[str] = None
    request_id: Optional[str] = None


# --- Network / Firewall ---

class NetworkFlowAnalyzeRequest(IntegrationBaseRequest):
    """Request to analyze network traffic via the firewall integration."""
    source_ip: str = Field(..., min_length=1)
    destination_ip: str = Field(..., min_length=1)
    port: int
    protocol: str = "tcp"  # tcp | udp
    bytes_transferred: int = 0
    flow_id: Optional[str] = None
    api_logs: Optional[list[dict[str, Any]]] = None


# --- Authentication / SSO ---

class AuthLoginAnalyzeRequest(IntegrationBaseRequest):
    """Request to analyze a login attempt via the SSO integration."""
    user_id: str = Field(..., min_length=1)
    source_ip: str = Field(..., min_length=1)
    user_agent: Optional[str] = None
    device_fingerprint: Optional[str] = None
    login_attempt_id: Optional[str] = None
    location: Optional[str] = None  # e.g., "London, UK"
    timestamp: Optional[str] = None
    # Optional recent login history from the IdP (same dict shape as the ATO
    # detector's events) so impossible-travel/burst heuristics can correlate.
    recent_events: Optional[list[dict[str, Any]]] = None


# --- Media / Content Moderation ---

class MediaAnalyzeRequest(IntegrationBaseRequest):
    """Request to analyze media via the content moderation integration (metadata-based; binary upload stays on /analysis/media)."""
    media_type: str = Field(..., description="image | video | audio")
    file_url: Optional[str] = None  # URL to the media file
    file_hash: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    media_id: Optional[str] = None
