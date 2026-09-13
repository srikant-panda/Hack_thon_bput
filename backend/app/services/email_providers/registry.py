"""Honest provider registry: only Gmail connects in Phase 1-2.

Every other provider is declared with an explicit coming-soon / unsupported
status — the UI must reflect exactly this, never fake a connection.
"""

from app.core.config import get_settings
from app.services.email_providers.base import ProviderCapability, ProviderRegistryEntry

_GMAIL_CAPABILITY = ProviderCapability(
    read_messages=True,       # Gmail API: messages.list / get (Phase 3)
    read_attachments=True,    # Gmail API: attachments.get (Phase 3)
    modify_labels=True,       # Gmail API: labels on gmail.modify scope
    quarantine=True,          # implemented as archive + "CyberGuard-Quarantine" label (Phase 4)
    trash=True,               # Gmail API: messages.trash
    permanent_delete=True,    # Gmail API: messages.delete (requires explicit consent; Phase 4)
    sender_rules=True,        # Gmail filters API via gmail.settings.basic scope
    send_mail=True,           # gmail.modify grants send; not used until declared
)

_OUTLOOK_CAPABILITY = ProviderCapability(
    read_messages=False,
    read_attachments=False,
    modify_labels=False,
    quarantine=False,
    trash=False,
    permanent_delete=False,
    sender_rules=False,
    send_mail=False,
    unsupported_reason="Microsoft Graph connector arrives with the Orgs Phase",
)

_YAHOO_CAPABILITY = ProviderCapability(
    read_messages=False,
    read_attachments=False,
    modify_labels=False,
    quarantine=False,
    trash=False,
    permanent_delete=False,
    sender_rules=False,
    send_mail=False,
    unsupported_reason="Yahoo Mail has no third-party OAuth API",
)

_ICLOUD_CAPABILITY = ProviderCapability(
    read_messages=False,
    read_attachments=False,
    modify_labels=False,
    quarantine=False,
    trash=False,
    permanent_delete=False,
    sender_rules=False,
    send_mail=False,
    unsupported_reason="iCloud Mail has no third-party OAuth API",
)


def gmail_configured() -> bool:
    settings = get_settings()
    return bool(
        settings.GMAIL_CONNECTOR_ENABLED
        and settings.GOOGLE_GMAIL_CLIENT_ID
        and settings.GOOGLE_GMAIL_CLIENT_SECRET
        and settings.CONNECTOR_TOKEN_KEY
    )


def get_registry() -> list[ProviderRegistryEntry]:
    settings = get_settings()
    gmail_status = "enabled" if gmail_configured() else "coming_soon"
    gmail_detail = ""
    if not settings.GMAIL_CONNECTOR_ENABLED:
        gmail_detail = "Gmail connector disabled via GMAIL_CONNECTOR_ENABLED"
    elif not settings.GOOGLE_GMAIL_CLIENT_ID or not settings.GOOGLE_GMAIL_CLIENT_SECRET:
        gmail_detail = "Missing GOOGLE_GMAIL_CLIENT_ID / GOOGLE_GMAIL_CLIENT_SECRET"
    elif not settings.CONNECTOR_TOKEN_KEY:
        gmail_detail = "Missing CONNECTOR_TOKEN_KEY (token encryption is required)"

    return [
        ProviderRegistryEntry(
            provider="gmail",
            display_name="Gmail",
            status=gmail_status,
            capabilities=_GMAIL_CAPABILITY if gmail_status == "enabled" else None,
            detail=gmail_detail,
        ),
        ProviderRegistryEntry(
            provider="outlook",
            display_name="Outlook",
            status="coming_soon",
            capabilities=None,
            detail=_OUTLOOK_CAPABILITY.unsupported_reason,
        ),
        ProviderRegistryEntry(
            provider="yahoo",
            display_name="Yahoo Mail",
            status="unsupported",
            capabilities=None,
            detail=_YAHOO_CAPABILITY.unsupported_reason,
        ),
        ProviderRegistryEntry(
            provider="icloud",
            display_name="iCloud Mail",
            status="unsupported",
            capabilities=None,
            detail=_ICLOUD_CAPABILITY.unsupported_reason,
        ),
    ]
