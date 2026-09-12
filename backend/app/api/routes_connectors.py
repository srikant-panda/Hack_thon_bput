"""Email connector endpoints (Phase 1-2: Gmail only).

All endpoints require the authenticated user except the OAuth callback,
which validates a single-use, high-entropy state row instead. Connector
responses never contain token material.
"""

import logging

from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import NotFoundError, PermissionDeniedError
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
from app.services.connectors import connector_service
from app.services.connectors.oauth_service import OAuthFlowError, create_gmail_authorization_url, handle_gmail_callback
from app.services.email_providers.registry import get_registry

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
