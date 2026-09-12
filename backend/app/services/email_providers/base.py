"""Provider-neutral email connector contract.

Phase 1-2 implements the connection/validation surface only. Mailbox scanning
(Phase 3) and quarantine/sender actions (Phase 4) will extend this interface.
"""

from dataclasses import dataclass, field, asdict
from typing import Protocol


@dataclass
class ProviderCapability:
    """Honest capability declaration for a provider integration."""

    read_messages: bool
    read_attachments: bool
    modify_labels: bool
    quarantine: bool
    trash: bool
    permanent_delete: bool
    sender_rules: bool
    send_mail: bool
    unsupported_reason: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ConnectorStatus:
    """Lifecycle status values for EmailConnectorAccount."""

    CONNECTED = "connected"
    REAUTH_REQUIRED = "reauth_required"
    REVOKED = "revoked"
    ERROR = "error"


class ProviderErrorClass:
    """Error classes surfaced to users — never raw provider payloads."""

    REAUTH_REQUIRED = "reauth_required"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    RATE_LIMITED = "rate_limited"
    FAILED = "failed"


@dataclass
class ProviderRegistryEntry:
    provider: str
    display_name: str
    status: str  # enabled | coming_soon | unsupported
    capabilities: ProviderCapability | None = None
    detail: str = ""


class EmailProviderError(Exception):
    """Provider-backed failure with a safe, user-facing error class."""

    def __init__(self, error_class: str, message: str, provider_code: str | None = None, provider_detail: str | None = None):
        super().__init__(message)
        self.error_class = error_class
        self.message = message
        self.provider_code = provider_code
        self.provider_detail = provider_detail


class EmailProvider(Protocol):
    """Provider-neutral contract. Phase 1-2: profile + connection test only;
    mailbox scanning (Phase 3) and enforcement actions (Phase 4) extend this."""

    provider: str
    capabilities: ProviderCapability

    async def get_profile(self, access_token: str) -> dict: ...

    async def test_connection(self, access_token: str) -> dict: ...
