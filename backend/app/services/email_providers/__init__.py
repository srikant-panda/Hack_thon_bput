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
from app.services.email_providers.mock_provider import MockEmailProvider, mock_provider

def get_provider(name: str | None):
    """Resolve a provider by connector.provider name (Phase 6: the engine
    never imports Gmail directly). Raises an honest unsupported error for
    unknown providers."""
    providers = {"gmail": gmail_provider, "mock": mock_provider}
    provider = providers.get(name or "")
    if provider is None:
        raise EmailProviderError(
            ProviderErrorClass.FAILED,
            f"Email provider '{name}' is not supported.",
            provider_code="unsupported_provider",
        )
    return provider


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
    "mock_provider",
    "MockEmailProvider",
    "get_provider",
    "gmail_configured",
    "get_registry",
]
