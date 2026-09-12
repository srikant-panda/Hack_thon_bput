"""Email connector endpoints (Phase 1-2: Gmail only).

All endpoints require the authenticated user except the OAuth callback,
which validates a single-use, high-entropy state row instead. Connector
responses never contain token material.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError, NotFoundError, PermissionDeniedError
from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.schemas.connectors import (
    ConnectorAccountRead,
    ConnectorAuthorizeRequest,
    ConnectorAuthorizeResponse,
    ConnectorCapabilitiesResponse,
    ConnectorDisconnectResponse,
    ConnectorListResponse,
    ConnectorOperationListResponse,
    ConnectorOperationRead,
    ConnectorTestResponse,
)
from app.schemas.email import MessageSummary, NormalizedMessage
from app.services.action_engine import enforce_scan_results
from app.schemas.scan_results import ScanResult
from app.services.connectors import connector_service
from app.services.connectors.oauth_service import OAuthFlowError, create_gmail_authorization_url, handle_gmail_callback
from app.services.connectors.token_manager import TokenRefreshError, get_valid_access_token
from app.services.email_providers.base import EmailProviderError
from app.services.email_providers.gmail import gmail_provider
from app.services.email_providers.registry import get_registry
from app.services.mail_scanner import scan_message

logger = logging.getLogger("cyberguard.connectors.api")

router = APIRouter(prefix="/connectors", tags=["Email Connectors"])

_MAX_SCAN_MESSAGES = 25
_BODY_PREVIEW_CHARS = 300


class ScanRequest(BaseModel):
    message_ids: Optional[list[str]] = None
    scan_recent: Optional[int] = Field(default=None, ge=1, le=25)


def _provider_error(exc: Exception) -> AppError:
    """Map provider/token failures to honest, safe API errors."""
    error_class = getattr(exc, "error_class", None) or "failed"
    if error_class == "reauth_required":
        return PermissionDeniedError("Mailbox authorization expired — reconnect this connector.")
    if error_class == "insufficient_scope":
        return AppError(
            "Gmail access was denied — the granted scopes are insufficient for this operation.",
            code="insufficient_scope",
            status_code=403,
        )
    return AppError(
        f"Email provider error: {exc}",
        code="provider_error",
        status_code=502,
    )


async def _require_owned_connector(connector_id: str, user: CurrentUser, db: AsyncSession):
    """Ownership gate: users can only touch their own connectors (RLS + filter)."""
    connector = await connector_service.get_connector(db, connector_id, user.id)
    if connector is None:
        raise NotFoundError("Email connector", connector_id)
    if connector.status == "revoked":
        raise PermissionDeniedError("This connector is disconnected — reconnect it first.")
    return connector


def _to_summary(message: NormalizedMessage) -> MessageSummary:
    text = message.body_text or ""
    return MessageSummary(
        provider_message_id=message.provider_message_id,
        provider=message.provider,
        sender=message.sender,
        recipients=message.recipients,
        subject=message.subject,
        received_at=message.received_at,
        is_read=message.is_read,
        has_attachments=bool(message.attachments_meta),
        body_preview=text[:_BODY_PREVIEW_CHARS],
    )

logger = logging.getLogger("cyberguard.connectors.api")

router = APIRouter(prefix="/connectors", tags=["Email Connectors"])


def _safe_reason(exc: OAuthFlowError) -> str:
    """Map flow failures to a safe redirect reason (no provider payloads)."""
    allowed = {
        "invalid_state": "invalid_state",
        "token_exchange_failed": "token_exchange_failed",
        "missing_refresh_token": "missing_refresh_token",
        "profile_failed": "profile_failed",
        "not_configured": "not_configured",
    }
    return allowed.get(exc.reason, "failed")


@router.get("/capabilities", response_model=ConnectorCapabilitiesResponse)
async def connector_capabilities() -> ConnectorCapabilitiesResponse:
    """Honest provider registry: Gmail only, others declared coming soon/unsupported."""
    items = [
        {
            "provider": entry.provider,
            "display_name": entry.display_name,
            "status": entry.status,
            "capabilities": entry.capabilities.to_dict() if entry.capabilities else None,
            "detail": entry.detail,
        }
        for entry in get_registry()
    ]
    return ConnectorCapabilitiesResponse(items=items)


@router.get("/operations", response_model=ConnectorOperationListResponse)
async def connector_operations(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
) -> ConnectorOperationListResponse:
    logs = await connector_service.list_operations(db, user.id, limit=min(limit, 200))
    return ConnectorOperationListResponse(items=[ConnectorOperationRead(**connector_service.serialize_operation(l)) for l in logs])


@router.get("", response_model=ConnectorListResponse)
async def list_connectors(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorListResponse:
    connectors = await connector_service.list_connectors(db, user.id)
    return ConnectorListResponse(
        items=[ConnectorAccountRead(**connector_service.serialize_connector(c)) for c in connectors]
    )


@router.post("/gmail/authorize", response_model=ConnectorAuthorizeResponse)
async def gmail_authorize(
    payload: ConnectorAuthorizeRequest | None = None,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorAuthorizeResponse:
    """Create a single-use OAuth state and return the Google consent URL."""
    redirect_after = payload.redirect_after if payload else None
    if not get_settings().GMAIL_CONNECTOR_ENABLED:
        raise PermissionDeniedError("Gmail connector is disabled")
    try:
        url = await create_gmail_authorization_url(db, user.id, redirect_after)
    except OAuthFlowError as exc:
        raise PermissionDeniedError(exc.message)
    return ConnectorAuthorizeResponse(authorization_url=url)


@router.get("/gmail/callback", include_in_schema=False)
async def gmail_callback(code: str | None = None, state: str | None = None) -> RedirectResponse:
    """OAuth callback: no bearer token here — the single-use state row carries
    the owner. Redirects to the frontend with a safe status; never tokens."""
    settings = get_settings()
    frontend = settings.FRONTEND_CONNECTORS_URL

    if not code or not state:
        return RedirectResponse(f"{frontend}?connected=gmail&status=error&reason=missing_parameters")

    try:
        connector = await handle_gmail_callback(code, state)
        logger.info("Gmail connector connected for owner=%s (%s)", connector.owner_user_id, connector.provider_email)
        return RedirectResponse(f"{frontend}?connected=gmail&status=success")
    except OAuthFlowError as exc:
        logger.warning("Gmail callback failed: %s (%s)", exc.reason, exc.message)
        return RedirectResponse(f"{frontend}?connected=gmail&status=error&reason={_safe_reason(exc)}")
    except RuntimeError as exc:
        # e.g. missing CONNECTOR_TOKEN_KEY — loud, honest failure
        logger.error("Gmail callback configuration error: %s", exc)
        return RedirectResponse(f"{frontend}?connected=gmail&status=error&reason=server_configuration")
    except Exception:  # noqa: BLE001
        logger.exception("Unexpected Gmail callback failure")
        return RedirectResponse(f"{frontend}?connected=gmail&status=error&reason=failed")


@router.post("/{connector_id}/test", response_model=ConnectorTestResponse)
async def test_connector(
    connector_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorTestResponse:
    connector = await connector_service.get_connector(db, connector_id, user.id)
    if connector is None:
        raise NotFoundError("Email connector", connector_id)
    result = await connector_service.test_connector(db, connector)
    return ConnectorTestResponse(**result)


@router.delete("/{connector_id}", response_model=ConnectorDisconnectResponse)
async def disconnect_connector(
    connector_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorDisconnectResponse:
    connector = await connector_service.get_connector(db, connector_id, user.id)
    if connector is None:
        raise NotFoundError("Email connector", connector_id)
    await connector_service.disconnect_connector(db, connector)
    return ConnectorDisconnectResponse(id=connector.id, status=connector.status)


# ---------------------------------------------------------------------------
# Mailbox scanning (Phase 3 — analysis only, no provider write operations)
# ---------------------------------------------------------------------------


@router.get("/{connector_id}/messages", response_model=list[MessageSummary])
async def list_connector_messages(
    connector_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=50),
) -> list[MessageSummary]:
    """List recent mailbox messages as normalized metadata (no heavy bodies)."""
    connector = await _require_owned_connector(connector_id, user, db)
    try:
        access_token = await get_valid_access_token(connector, db)
        message_ids = await gmail_provider.list_messages(access_token, max_results=limit)
        messages = []
        for entry in message_ids:
            messages.append(await gmail_provider.get_message(access_token, entry["id"]))
    except (EmailProviderError, TokenRefreshError) as exc:
        raise _provider_error(exc) from exc
    return [_to_summary(m) for m in messages]


@router.post("/{connector_id}/scan", response_model=list[ScanResult])
async def scan_connector_messages(
    connector_id: str,
    payload: ScanRequest | None = None,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ScanResult]:
    """Fetch messages via the token manager and run the detection pipeline.

    Ownership is enforced by the connector lookup (owner filter + RLS);
    analysis only — enforcement actions are reported as deferred_to_phase_4.
    """
    connector = await _require_owned_connector(connector_id, user, db)
    payload = payload or ScanRequest()

    try:
        access_token = await get_valid_access_token(connector, db)
        if payload.message_ids:
            message_ids = payload.message_ids[:_MAX_SCAN_MESSAGES]
        else:
            recent = min(payload.scan_recent or 10, _MAX_SCAN_MESSAGES)
            entries = await gmail_provider.list_messages(access_token, max_results=recent)
            message_ids = [entry["id"] for entry in entries]

        pairs: list[tuple[NormalizedMessage, ScanResult]] = []
        for message_id in message_ids:
            message = await gmail_provider.get_message(access_token, message_id)
            pairs.append((message, await scan_message(message)))
    except (EmailProviderError, TokenRefreshError) as exc:
        raise _provider_error(exc) from exc

    # Phase 4: run the action engine on the fresh scan results. Provider
    # failures are recorded per-message in the ScanResult (honest reporting),
    # they do not fail the whole scan.
    results = await enforce_scan_results(db, connector, pairs)

    connector.last_sync_at = datetime.now(timezone.utc)
    await db.commit()
    return results


@router.get("/{connector_id}/messages/{message_id}/analysis")
async def get_message_analysis(
    connector_id: str,
    message_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Full ScanResult plus the full normalized message for the review view."""
    connector = await _require_owned_connector(connector_id, user, db)
    try:
        access_token = await get_valid_access_token(connector, db)
        message = await gmail_provider.get_message(access_token, message_id)
    except (EmailProviderError, TokenRefreshError) as exc:
        raise _provider_error(exc) from exc
    scan_result = await scan_message(message)
    return {"scan": scan_result, "message": message}
