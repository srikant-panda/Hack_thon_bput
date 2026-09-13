"""Provider-neutral email connector contract (finalized Phase 6).

The security engine (action_engine, scheduler, scanner wiring) interacts with
providers ONLY through this interface — never through Gmail-specific code.
Every provider declares its true capabilities via the ``capabilities``
property; callers must consult it instead of guessing.
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

    def flags(self) -> dict:
        """Boolean capability flags for engine queries (Phase 6)."""
        d = self.to_dict()
        d["supports_read"] = self.read_messages
        d["supports_attachments"] = self.read_attachments
        d["supports_modify"] = self.modify_labels
        d["supports_quarantine"] = self.quarantine
        d["supports_trash"] = self.trash
        d["supports_permanent_delete"] = self.permanent_delete
        d["supports_sender_rules"] = self.sender_rules
        d["supports_send"] = self.send_mail
        return d


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
    """Provider-neutral contract — the 14 methods mandated by the Phase 6
    spec, plus the operational extensions the platform uses (profile /
    test_connection / release_message / ensure_quarantine_label).

    Callers MUST check ``capabilities`` before using a method the provider
    may not support."""

    provider: str
    quarantine_label_name: str

    @property
    def capabilities(self) -> dict: ...

    # --- 1. authorization lifecycle ---
    async def authorize(self, *, redirect_uri: str, state: str) -> dict: ...
    """Return {authorization_url} for the OAuth consent screen."""

    async def refresh_token(self, refresh_token: str) -> dict: ...
    """Return {access_token, expires_in, [refresh_token]} from a refresh token."""

    # --- 2. reading ---
    async def list_messages(self, access_token: str, max_results: int = 50) -> list[dict]: ...
    async def get_message(self, access_token: str, message_id: str) -> object: ...
    async def get_attachment(self, access_token: str, message_id: str, attachment_id: str) -> dict: ...

    # --- 3. composing ---
    async def create_draft(self, access_token: str, raw_mime: str, thread_id: str | None = None) -> dict: ...
    async def send_message(self, access_token: str, raw_mime: str, thread_id: str | None = None) -> dict: ...

    # --- 4. message actions ---
    async def modify_message(
        self, access_token: str, message_id: str,
        add_label_ids: list[str] | None = None, remove_label_ids: list[str] | None = None,
    ) -> dict: ...
    async def move_to_trash(self, access_token: str, message_id: str) -> dict: ...
    async def delete_message(self, access_token: str, message_id: str, permanent: bool) -> dict: ...
    async def quarantine_message(self, access_token: str, message_id: str, quarantine_label: str) -> dict: ...
    async def release_message(self, access_token: str, message_id: str, quarantine_label: str) -> dict: ...

    # --- 5. sender rules ---
    async def create_sender_rule(self, access_token: str, sender_email: str, target_label: str) -> dict: ...
    async def update_sender_rule(self, access_token: str, rule_id: str, sender_email: str, target_label: str) -> dict: ...
    async def delete_sender_rule(self, access_token: str, rule_id: str) -> dict: ...

    # --- operational extensions (not part of the 14) ---
    async def get_profile(self, access_token: str) -> dict: ...
    async def test_connection(self, access_token: str) -> dict: ...
    async def ensure_quarantine_label(self, access_token: str) -> str: ...
