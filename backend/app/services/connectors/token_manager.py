"""Token lifecycle for email connectors.

Access tokens live encrypted at rest and are decrypted only in runtime while
a provider call executes. Refresh happens transparently against the Google
token endpoint; on ``invalid_grant`` the connector is marked
``reauth_required`` and a typed error is raised.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.crypto import decrypt_secret, encrypt_secret
from app.db.models import ConnectorOperationLog, EmailConnectorAccount
from app.services.email_providers.base import ConnectorStatus, ProviderErrorClass
from app.services.email_providers.gmail import GOOGLE_TOKEN_URL, gmail_provider

logger = logging.getLogger("cyberguard.connectors.tokens")

_EXPIRY_MARGIN_SECONDS = 60


class TokenRefreshError(Exception):
    """Refresh failed; ``error_class`` is a safe ProviderErrorClass value."""

    def __init__(self, error_class: str, message: str, provider_code: str | None = None):
        super().__init__(message)
        self.error_class = error_class
        self.message = message
        self.provider_code = provider_code


async def _refresh_access_token(refresh_token: str) -> dict:
    settings = get_settings()
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
        response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": settings.GOOGLE_GMAIL_CLIENT_ID,
                "client_secret": settings.GOOGLE_GMAIL_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        )
    payload = {}
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        pass
    if response.status_code != 200:
        code = str(payload.get("error") or "")
        if code == "invalid_grant" or response.status_code == 401:
            raise TokenRefreshError(
                ProviderErrorClass.REAUTH_REQUIRED,
                "Google rejected the refresh token — reconnect this mailbox.",
                provider_code=code or None,
            )
        raise TokenRefreshError(
            ProviderErrorClass.FAILED,
            f"Token refresh failed (HTTP {response.status_code}).",
            provider_code=code or None,
        )
    if not payload.get("access_token"):
        raise TokenRefreshError(ProviderErrorClass.FAILED, "Token refresh returned no access token.")
    return payload


async def _mark_reauth_required(db: AsyncSession, connector: EmailConnectorAccount, message: str) -> None:
    connector.status = ConnectorStatus.REAUTH_REQUIRED
    connector.last_error = message
    db.add(
        ConnectorOperationLog(
            id=str(uuid.uuid4()),
            owner_user_id=connector.owner_user_id,
            connector_id=connector.id,
            provider=connector.provider,
            operation="token_refresh",
            status="reauth_required",
            message=message,
        )
    )
    await db.commit()


async def get_valid_access_token(connector: EmailConnectorAccount, db: AsyncSession) -> str:
    """Return a decrypted access token, refreshing it when close to expiry.

    Never stores or logs plaintext outside runtime variables.
    """
    now = datetime.now(timezone.utc)

    if connector.access_token_enc and connector.access_token_expires_at:
        expires_at = connector.access_token_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at > now + timedelta(seconds=_EXPIRY_MARGIN_SECONDS):
            return decrypt_secret(connector.access_token_enc)

    if not connector.refresh_token_enc:
        raise TokenRefreshError(
            ProviderErrorClass.REAUTH_REQUIRED,
            "No refresh token stored — reconnect this mailbox.",
        )

    refresh_token = decrypt_secret(connector.refresh_token_enc)
    try:
        payload = await _refresh_access_token(refresh_token)
    except TokenRefreshError as exc:
        if exc.error_class == ProviderErrorClass.REAUTH_REQUIRED:
            await _mark_reauth_required(db, connector, exc.message)
        raise

    access_token = payload["access_token"]
    expires_in = int(payload.get("expires_in") or 3600)
    connector.access_token_enc = encrypt_secret(access_token)
    connector.access_token_expires_at = now + timedelta(seconds=expires_in)
    connector.status = ConnectorStatus.CONNECTED
    connector.last_error = None

    # Google may rotate the refresh token on refresh (rare).
    if payload.get("refresh_token"):
        connector.refresh_token_enc = encrypt_secret(payload["refresh_token"])

    db.add(
        ConnectorOperationLog(
            id=str(uuid.uuid4()),
            owner_user_id=connector.owner_user_id,
            connector_id=connector.id,
            provider=connector.provider,
            operation="token_refresh",
            status="success",
            message="Access token refreshed",
        )
    )
    await db.commit()
    return access_token


async def validate_access_token(access_token: str) -> dict:
    """Lightweight validation via the Gmail profile endpoint (used at callback)."""
    return await gmail_provider.get_profile(access_token)
