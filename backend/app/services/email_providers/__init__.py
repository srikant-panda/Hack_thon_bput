"""Email provider integrations (Phase 1-2: Gmail only)."""

from app.services.email_providers.base import (
    ConnectorStatus,
    EmailProvider,
    EmailProviderError,
    ProviderCapability,
    ProviderErrorClass,
    ProviderRegistryEntry,
)
from app.services.email_providers.registry import get_registry, gmail_configured
from app.services.email_providers.gmail import GMAIL_SCOPE, GmailProvider, gmail_provider

__all__ = [
    "ConnectorStatus",
    "EmailProvider",
    "EmailProviderError",
    "GMAIL_SCOPE",
    "GmailProvider",
    "ProviderCapability",
    "ProviderErrorClass",
    "ProviderRegistryEntry",
    "gmail_provider",
    "gmail_configured",
    "get_registry",
]
