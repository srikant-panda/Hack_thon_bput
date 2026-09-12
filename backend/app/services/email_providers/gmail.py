"""Gmail provider implementation (Phase 1-2: profile + connection test).

Uses CYBERGUARD's own Google OAuth client; access tokens are minted by
app/services/connectors/oauth_service.py and decrypted only in runtime.
"""

import logging

import httpx

from app.services.email_providers.base import (
    EmailProviderError,
    ProviderCapability,
    ProviderErrorClass,
)

logger = logging.getLogger("cyberguard.connectors.gmail")

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify"

_TIMEOUT = httpx.Timeout(15.0)


class GmailProvider:
    provider = "gmail"
    capabilities = ProviderCapability(
        read_messages=True,
        read_attachments=True,
        modify_labels=True,
        quarantine=True,
        trash=True,
        permanent_delete=True,
        sender_rules=False,
        send_mail=True,
    )

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._client = http_client or httpx.AsyncClient(timeout=_TIMEOUT)

    def _error(self, status_code: int, payload: dict | None) -> EmailProviderError:
        """Map Google errors to safe, user-facing error classes."""
        body = payload or {}
        detail = str(body.get("error_description") or body.get("error") or body.get("message") or "")
        code = str(body.get("error") or body.get("status") or "")

        if status_code == 401 or "invalid_grant" in code or "expired" in detail.lower():
            return EmailProviderError(
                ProviderErrorClass.REAUTH_REQUIRED,
                "Gmail authorization expired — reconnect this mailbox.",
                provider_code=code or None,
                provider_detail=detail or None,
            )
        if status_code == 403 or "insufficientPermissions" in code or "insufficient" in detail.lower():
            return EmailProviderError(
                ProviderErrorClass.INSUFFICIENT_SCOPE,
                "Gmail access was denied — the granted scopes are insufficient.",
                provider_code=code or None,
                provider_detail=detail or None,
            )
        if status_code == 429 or "rateLimitExceeded" in code:
            return EmailProviderError(
                ProviderErrorClass.RATE_LIMITED,
                "Gmail rate limit reached — try again shortly.",
                provider_code=code or None,
                provider_detail=detail or None,
            )
        return EmailProviderError(
            ProviderErrorClass.FAILED,
            f"Gmail request failed (HTTP {status_code}).",
            provider_code=code or None,
            provider_detail=detail or None,
        )

    async def _request(self, method: str, url: str, access_token: str, **kwargs) -> dict:
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            response = await self._client.request(method, url, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise EmailProviderError(
                ProviderErrorClass.FAILED, f"Gmail request failed: {type(exc).__name__}"
            ) from exc
        if response.status_code >= 400:
            try:
                payload = response.json()
            except Exception:  # noqa: BLE001
                payload = {}
            raise self._error(response.status_code, payload)
        if not response.content:
            return {}
        return response.json()

    async def get_profile(self, access_token: str) -> dict:
        """GET /users/me/profile → {email_address, messages_total, ...}."""
        return await self._request("GET", f"{GMAIL_API_BASE}/users/me/profile", access_token)

    async def test_connection(self, access_token: str) -> dict:
        """Validate the token against the profile endpoint; return safe summary."""
        profile = await self.get_profile(access_token)
        return {
            "provider": self.provider,
            "email_address": profile.get("email_address"),
            "messages_total": profile.get("messages_total"),
            "threads_total": profile.get("threads_total"),
            "ok": True,
        }

    async def close(self) -> None:
        await self._client.aclose()


gmail_provider = GmailProvider()
