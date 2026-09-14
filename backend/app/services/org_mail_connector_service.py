"""Org-level mail server connectors (ORG-3) — server-to-server infrastructure.

This is deliberately NOT the personal Gmail OAuth connector (Phase 2): an org
mail server is a piece of infrastructure (Google Workspace admin API with
domain-wide delegation, Microsoft Graph app-only consent, generic IMAP/SMTP)
managed like any other server asset, with its own credential blob, settings,
and log stream.

Transport architecture: the connector classes below are provider protocol
adapters; the actual wire calls go through a pluggable *transport*
(``ORG_MAIL_TRANSPORTS``). The shipped default is ``SimulationTransport``,
which performs real credential validation and returns clearly-flagged
simulated results — the same honest-simulation pattern as
``action_executor``. Dropping in the real drivers (``google-api-python-
client`` for domain-wide delegation, ``msal`` client-credentials flow for
Graph, stdlib ``imaplib`` for IMAP/SMTP) is a transport registration — no
changes to the service, routes, or UI. (The named driver packages are not in
the dependency set, and this phase adds no new dependencies.)

Credentials: provider-specific JSON, Fernet-encrypted at rest via
``app.core.crypto`` (shared ``CONNECTOR_TOKEN_KEY``); plaintext never lands
in the database, logs, or API responses.
"""

import json
import logging
from typing import Any, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.errors import ValidationError
from app.db.models import OrgMailServer, OrgMailServerLog

logger = logging.getLogger("cyberguard.org_mail")

PROVIDER_TYPES = ("google_workspace", "microsoft_365", "imap_smtp")

# Required credential fields per provider (validated on connect).
CREDENTIAL_SCHEMAS: dict[str, tuple[str, ...]] = {
    "google_workspace": ("service_account_key", "delegated_user"),
    "microsoft_365": ("client_id", "client_secret", "tenant_id"),
    "imap_smtp": ("host", "port", "username", "password"),
}

DEFAULT_SETTINGS: dict[str, dict[str, Any]] = {
    "scan_interval_seconds": {"value": 300},
    "quarantine_enabled": {"value": True},
    "auto_block_malicious_senders": {"value": False},
    "quarantine_expiry_hours": {"value": 24},
}


class TransportError(Exception):
    """Raised by a transport when a provider call fails."""


def _validate_credentials(provider_type: str, credentials: dict[str, Any]) -> dict[str, Any]:
    if provider_type not in PROVIDER_TYPES:
        raise ValidationError(f"provider_type must be one of {list(PROVIDER_TYPES)}")
    if not isinstance(credentials, dict):
        raise ValidationError("credentials must be an object")
    missing = [f for f in CREDENTIAL_SCHEMAS[provider_type] if not credentials.get(f)]
    if missing:
        raise ValidationError(f"Missing credential fields for {provider_type}: {missing}")
    return credentials


# ---------------------------------------------------------------------------
# Pluggable transports (the wire protocol seam)
# ---------------------------------------------------------------------------


class SimulationTransport:
    """Default transport: validates inputs and simulates provider calls.

    Every result is flagged ``"simulated": True``; org_mail_server_logs
    entries carry ``mode: simulated`` so operators are never misled.
    """

    mode = "simulated"

    async def verify(self, provider_type: str, credentials: dict[str, Any]) -> dict[str, Any]:
        return {
            "simulated": True,
            "provider": provider_type,
            "verified": CREDENTIAL_SCHEMAS[provider_type],
        }

    async def fetch_recent_emails(
        self, provider_type: str, credentials: dict[str, Any], limit: int
    ) -> list[dict[str, Any]]:
        return []

    async def quarantine_email(
        self, provider_type: str, credentials: dict[str, Any], message_id: str
    ) -> dict[str, Any]:
        return {"simulated": True, "message_id": message_id, "quarantined": True}


ORG_MAIL_TRANSPORTS: dict[str, Any] = {
    "google_workspace": SimulationTransport(),
    "microsoft_365": SimulationTransport(),
    "imap_smtp": SimulationTransport(),
}


def get_transport(provider_type: str) -> Any:
    transport = ORG_MAIL_TRANSPORTS.get(provider_type)
    if transport is None:
        raise ValidationError(f"No transport registered for {provider_type}")
    return transport


# ---------------------------------------------------------------------------
# Connector classes (protocol adapters over a transport)
# ---------------------------------------------------------------------------


class OrgMailConnector:
    """Base class for org-level mail server connectors."""

    provider_type: ClassVar[str] = ""

    async def connect(self, mail_server: OrgMailServer, credentials: dict[str, Any]) -> dict[str, Any]:
        """Validate credentials, encrypt, and mark the server connected."""
        creds = _validate_credentials(self.provider_type, credentials)
        verify = await get_transport(self.provider_type).verify(self.provider_type, creds)
        mail_server.credentials_encrypted = encrypt_secret(json.dumps(creds))
        mail_server.status = "connected"
        mail_server.last_connected_at = _utcnow()
        mail_server.last_error = None
        return verify

    async def reconnect(self, mail_server: OrgMailServer) -> dict[str, Any]:
        """Re-verify stored credentials (POST /connect without new creds)."""
        creds = self.decrypt_credentials(mail_server)
        return await get_transport(self.provider_type).verify(self.provider_type, creds)

    async def disconnect(self, mail_server: OrgMailServer) -> dict[str, Any]:
        """Graceful teardown: CYBERGUARD stops reading; the mail server keeps
        running untouched. Credentials are RETAINED for quick reconnect."""
        mail_server.status = "disconnected"
        return {"graceful": True, "credentials_retained": mail_server.credentials_encrypted is not None}

    async def fetch_recent_emails(
        self, mail_server: OrgMailServer, limit: int = 100
    ) -> list[dict[str, Any]]:
        if mail_server.status != "connected":
            raise TransportError(f"Mail server '{mail_server.name}' is not connected")
        creds = self.decrypt_credentials(mail_server)
        messages = await get_transport(self.provider_type).fetch_recent_emails(
            self.provider_type, creds, limit
        )
        return [self._normalize_message(m) for m in messages]

    async def quarantine_email(self, mail_server: OrgMailServer, message_id: str) -> dict[str, Any]:
        if mail_server.status != "connected":
            raise TransportError(f"Mail server '{mail_server.name}' is not connected")
        creds = self.decrypt_credentials(mail_server)
        return await get_transport(self.provider_type).quarantine_email(
            self.provider_type, creds, message_id
        )

    def decrypt_credentials(self, mail_server: OrgMailServer) -> dict[str, Any]:
        if not mail_server.credentials_encrypted:
            raise ValidationError("Mail server has no stored credentials — connect first")
        try:
            return json.loads(decrypt_secret(mail_server.credentials_encrypted))
        except Exception as exc:  # noqa: BLE001 - surface decrypt failures clearly
            raise ValidationError(
                "Stored credentials cannot be decrypted — the CONNECTOR_TOKEN_KEY changed. "
                "Reconnect this mail server."
            ) from exc

    def _normalize_message(self, message: dict[str, Any]) -> dict[str, Any]:
        """Normalize a provider message to the common scan-pipeline shape."""
        return {
            "message_id": str(message.get("message_id") or message.get("id") or ""),
            "sender": str(message.get("sender") or message.get("from") or ""),
            "subject": str(message.get("subject") or ""),
            "snippet": str(message.get("snippet") or message.get("body") or "")[:500],
            "received_at": message.get("received_at") or message.get("date"),
            "provider": self.provider_type,
        }


class GoogleWorkspaceConnector(OrgMailConnector):
    """Google Workspace admin API — service account with domain-wide
    delegation. Scopes: gmail.readonly, gmail.modify,
    admin.directory.user.readonly. Real driver: google-api-python-client."""

    provider_type = "google_workspace"


class Microsoft365Connector(OrgMailConnector):
    """Microsoft Graph app-only permissions with admin consent.
    Scopes: Mail.Read, Mail.ReadWrite, User.Read.All. Real driver: msal
    client-credentials flow."""

    provider_type = "microsoft_365"


class IMAPSMTPConnector(OrgMailConnector):
    """Generic IMAP/SMTP with app passwords (or OAuth via SASL XOAUTH2).
    Real driver: stdlib imaplib."""

    provider_type = "imap_smtp"


CONNECTORS: dict[str, OrgMailConnector] = {
    c.provider_type: c()
    for c in (GoogleWorkspaceConnector, Microsoft365Connector, IMAPSMTPConnector)
}


def get_connector(provider_type: str) -> OrgMailConnector:
    connector = CONNECTORS.get(provider_type)
    if connector is None:
        raise ValidationError(f"Unknown provider_type: {provider_type}")
    return connector


def _utcnow():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


async def log_server_event(
    db: AsyncSession,
    mail_server_id: str,
    log_type: str,
    message: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Append to this mail server's own log stream (per-server grouping)."""
    if log_type not in {"connection", "scan", "quarantine", "error"}:
        raise ValidationError(f"Invalid mail server log_type: {log_type}")
    db.add(OrgMailServerLog(
        mail_server_id=mail_server_id,
        log_type=log_type,
        message=message[:2000],
        metadata_json=metadata or {},
    ))
    await db.flush()
