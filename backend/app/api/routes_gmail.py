"""Gmail connection management and lifecycle API routes.

Provides endpoints for:
- POST /gmail/disconnect: stop watch, revoke tokens, clear credentials, mark DISCONNECTED.
- GET /gmail/status: return current connection status without exposing sensitive credentials.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.security import CurrentUser, get_current_user
from app.db.models import EmailConnectorAccount, GmailAccount
from app.db.session import get_db
from app.services.email_providers.base import ConnectorStatus
from app.services.email_providers.gmail import GOOGLE_REVOKE_URL
from app.services.gmail.client import GmailClient

logger = logging.getLogger("cyberguard.routes_gmail")

router = APIRouter(tags=["Gmail Lifecycle"])


class GmailDisconnectResponse(BaseModel):
    success: bool
    message: str


class GmailStatusResponse(BaseModel):
    connected: bool
    email: Optional[str] = None
    status: str = Field(description="ACTIVE or DISCONNECTED")


def get_gmail_client() -> GmailClient:
    """Dependency provider for GmailClient to allow overriding in tests."""
    return GmailClient()


async def revoke_token(token: str, timeout: float = 10.0) -> bool:
    """Best-effort Google OAuth token revocation."""
    if not token:
        return False
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(GOOGLE_REVOKE_URL, data={"token": token})
            if resp.status_code == 200:
                logger.info("Successfully revoked Google token")
                return True
            logger.warning("Google token revoke returned HTTP %d: %s", resp.status_code, resp.text)
            return False
    except Exception as exc:
        logger.warning("Could not reach Google revoke endpoint: %s", exc)
        return False


@router.post("/gmail/disconnect", response_model=GmailDisconnectResponse)
async def disconnect_gmail(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    gmail_client: GmailClient = Depends(get_gmail_client),
) -> GmailDisconnectResponse:
    """Disconnect Gmail integration for the current authenticated user.

    Idempotent operation:
    - 404 if no Gmail account exists for this user.
    - If status is already 'DISCONNECTED', returns success immediately without Google API calls.
    - If ACTIVE: calls gmail.users.stop, revokes Google OAuth token, marks DISCONNECTED,
      and cleans up stored credentials.
    """
    stmt = select(GmailAccount).where(GmailAccount.owner_user_id == current_user.id)
    account = (await db.execute(stmt)).scalar_one_or_none()

    if account is None:
        raise NotFoundError("Gmail account not found")

    # Idempotency: if already DISCONNECTED, return success without calling Google APIs
    if account.status == "DISCONNECTED":
        return GmailDisconnectResponse(success=True, message="Gmail disconnected")

    # 1. Load decrypted tokens before clearing
    refresh_token = account.get_refresh_token()
    access_token = account.get_access_token()

    # 2. Try gmail.users.stop(userId='me') — catch errors (already stopped = continue)
    try:
        await gmail_client.stop(
            access_token=access_token or "",
            refresh_token=refresh_token,
        )
    except Exception as exc:
        logger.warning("Error stopping Gmail push watch during disconnect for user %s: %s", current_user.id, exc)

    # 3. Try revoke_token() via Google's revoke endpoint — catch errors (already revoked = continue)
    token_to_revoke = refresh_token or access_token
    if token_to_revoke:
        try:
            await revoke_token(token_to_revoke)
        except Exception as exc:
            logger.warning("Error revoking Google token during disconnect: %s", exc)

    # 4. Update gmail_account: status='DISCONNECTED', disconnected_at=now(), clear tokens & checkpoints
    now = datetime.now(timezone.utc)
    account.status = "DISCONNECTED"
    account.disconnected_at = now
    account.set_refresh_token(None)
    account.set_access_token(None)
    account.last_history_id = None
    account.watch_expiration = None
    account.sync_status = "paused"
    account.updated_at = now

    # 5. Also update any mirrored EmailConnectorAccount
    conn_stmt = select(EmailConnectorAccount).where(
        EmailConnectorAccount.owner_user_id == current_user.id,
        EmailConnectorAccount.provider == "gmail",
    )
    connector = (await db.execute(conn_stmt)).scalar_one_or_none()
    if connector is not None:
        connector.status = ConnectorStatus.REVOKED
        connector.refresh_token_enc = None
        connector.access_token_enc = None
        connector.access_token_expires_at = None

    await db.commit()
    logger.info("Successfully disconnected Gmail account for user %s (%s)", current_user.id, account.email)
    return GmailDisconnectResponse(success=True, message="Gmail disconnected")


@router.get("/gmail/status", response_model=GmailStatusResponse)
async def get_gmail_status(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> GmailStatusResponse:
    """Get current Gmail connection status for the authenticated user.

    Never exposes tokens or internal Google IDs.
    """
    stmt = select(GmailAccount).where(GmailAccount.owner_user_id == current_user.id)
    account = (await db.execute(stmt)).scalar_one_or_none()

    if account is not None and account.status == "ACTIVE":
        return GmailStatusResponse(connected=True, email=account.email, status="ACTIVE")

    return GmailStatusResponse(connected=False, status="DISCONNECTED")
