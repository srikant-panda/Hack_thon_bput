"""ORG-3: org-level mail server connectors — server management surface.

Server-to-server infrastructure (Google Workspace / Microsoft 365 / IMAP),
NOT the personal Gmail connector. Per-server log grouping: every mail server
owns its own log stream and settings; disconnect is graceful (the mail
server keeps running, credentials are retained for reconnect).
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_secret
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.permissions import OrgRole, require_org_role
from app.core.security import CurrentUser, get_current_user
from app.db.models import OrgMailServer, OrgMailServerLog, OrgMailServerSetting, Organization
from app.db.session import get_db
from app.schemas.org_mail import (
    ConnectMailServerRequest,
    CreateMailServerRequest,
    FetchEmailsResponse,
    MailServerActionResponse,
    MailServerLogResponse,
    MailServerResponse,
    MailServerSettingsResponse,
    MailServerSettingsUpdate,
)
from app.services.org_mail_connector_service import (
    DEFAULT_SETTINGS,
    TransportError,
    get_connector,
    log_server_event,
)

logger = logging.getLogger("cyberguard.org_mail")

router = APIRouter(prefix="/org", tags=["Org Mail Servers"])


async def _get_server(db: AsyncSession, org_id: str, server_id: str) -> OrgMailServer:
    server = await db.get(OrgMailServer, server_id)
    if server is None or server.organization_id != org_id:
        raise NotFoundError("Mail server", server_id)
    return server


def _server_response(server: OrgMailServer) -> MailServerResponse:
    return MailServerResponse(
        id=server.id,
        name=server.name,
        provider_type=server.provider_type,
        status=server.status,
        last_connected_at=server.last_connected_at,
        last_error=server.last_error,
        has_credentials=server.credentials_encrypted is not None,
        created_at=server.created_at,
    )


@router.post("/{org_id}/mail-servers", response_model=MailServerResponse,
             status_code=status.HTTP_201_CREATED)
async def create_mail_server(
    org_id: str,
    payload: CreateMailServerRequest,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Register a mail server (admin). Attempts connection when credentials
    are provided; the result (success or failure) lands in the server's own
    log stream."""
    if await db.get(Organization, org_id) is None:
        raise NotFoundError("Organization", org_id)
    existing = await db.execute(
        select(OrgMailServer.id).where(
            OrgMailServer.organization_id == org_id,
            OrgMailServer.name == payload.name.strip(),
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Mail server name '{payload.name}' already exists in this organization")

    server = OrgMailServer(
        organization_id=org_id,
        name=payload.name.strip(),
        provider_type=payload.provider_type,
        status="disconnected",
        created_by=user.id,
    )
    db.add(server)
    await db.flush()
    await log_server_event(db, server.id, "connection", f"Mail server '{server.name}' registered")

    if payload.credentials and payload.connect_now:
        await _apply_connect(db, server, payload.credentials)

    # Seed default per-server settings.
    for key, spec in DEFAULT_SETTINGS.items():
        db.add(OrgMailServerSetting(
            mail_server_id=server.id, key=key, value=dict(spec),
            updated_by=user.id,
        ))

    await db.commit()
    await db.refresh(server)
    return _server_response(server)


async def _apply_connect(db: AsyncSession, server: OrgMailServer, credentials: dict) -> None:
    connector = get_connector(server.provider_type)
    try:
        detail = await connector.connect(server, credentials)
        await log_server_event(
            db, server.id, "connection",
            f"Connected to {server.provider_type} (mode: {detail.get('mode', 'simulated')})",
            {"mode": detail.get("mode", "simulated")},
        )
    except ValidationError as exc:
        server.status = "error"
        server.last_error = str(exc)
        await log_server_event(db, server.id, "error", f"Connect failed: {exc}")
        raise


@router.get("/{org_id}/mail-servers", response_model=list[MailServerResponse])
async def list_mail_servers(
    org_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(
        select(OrgMailServer)
        .where(OrgMailServer.organization_id == org_id)
        .order_by(OrgMailServer.created_at.desc())
    )
    return [_server_response(s) for s in result.scalars().all()]


@router.get("/{org_id}/mail-servers/{server_id}", response_model=MailServerResponse)
async def get_mail_server(
    org_id: str,
    server_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    return _server_response(await _get_server(db, org_id, server_id))


@router.post("/{org_id}/mail-servers/{server_id}/connect", response_model=MailServerActionResponse)
async def connect_mail_server(
    org_id: str,
    server_id: str,
    payload: ConnectMailServerRequest,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Connect using stored credentials, or rotate credentials inline."""
    server = await _get_server(db, org_id, server_id)
    connector = get_connector(server.provider_type)
    try:
        if payload.credentials:
            detail = await connector.connect(server, payload.credentials)
            await log_server_event(db, server.id, "connection", "Connected with new credentials",
                                   {"mode": detail.get("mode", "simulated")})
        else:
            detail = await connector.reconnect(server)
            server.status = "connected"
            server.last_connected_at = datetime.now(timezone.utc)
            server.last_error = None
            await log_server_event(db, server.id, "connection", "Connected using stored credentials",
                                   {"mode": detail.get("mode", "simulated")})
    except (ValidationError, TransportError) as exc:
        server.status = "error"
        server.last_error = str(exc)
        await log_server_event(db, server.id, "error", f"Connect failed: {exc}")
        await db.commit()
        raise ValidationError(f"Connect failed: {exc}")

    await db.commit()
    return MailServerActionResponse(id=server.id, status=server.status, detail=detail)


@router.post("/{org_id}/mail-servers/{server_id}/disconnect", response_model=MailServerActionResponse)
async def disconnect_mail_server(
    org_id: str,
    server_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Graceful disconnect: CYBERGUARD stops reading the server; the mail
    server itself stays operational and credentials are retained."""
    server = await _get_server(db, org_id, server_id)
    connector = get_connector(server.provider_type)
    detail = await connector.disconnect(server)
    await log_server_event(db, server.id, "connection", "Disconnected (graceful — mail server unaffected)")
    await db.commit()
    return MailServerActionResponse(id=server.id, status=server.status, detail=detail)


@router.delete("/{org_id}/mail-servers/{server_id}")
async def delete_mail_server(
    org_id: str,
    server_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    server = await _get_server(db, org_id, server_id)
    name = server.name
    await db.delete(server)  # settings + logs cascade
    await db.commit()
    return {"message": f"Mail server '{name}' deleted (credentials and logs removed)"}


@router.post("/{org_id}/mail-servers/{server_id}/fetch", response_model=FetchEmailsResponse)
async def fetch_recent_emails(
    org_id: str,
    server_id: str,
    limit: int = Query(default=25, ge=1, le=200),
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Pull recent messages for scanning (normalized to the common shape)."""
    server = await _get_server(db, org_id, server_id)
    connector = get_connector(server.provider_type)
    try:
        messages = await connector.fetch_recent_emails(server, limit)
    except TransportError as exc:
        server.last_error = str(exc)
        await log_server_event(db, server.id, "error", f"Fetch failed: {exc}")
        await db.commit()
        raise ValidationError(str(exc))
    await log_server_event(db, server.id, "scan", f"Fetched {len(messages)} message(s) for scanning",
                           {"count": len(messages)})
    await db.commit()
    return FetchEmailsResponse(mail_server_id=server.id, count=len(messages), messages=messages)


@router.post("/{org_id}/mail-servers/{server_id}/quarantine")
async def quarantine_message(
    org_id: str,
    server_id: str,
    payload: dict,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    message_id = str(payload.get("message_id") or "").strip()
    if not message_id:
        raise ValidationError("message_id is required")
    server = await _get_server(db, org_id, server_id)
    connector = get_connector(server.provider_type)
    try:
        detail = await connector.quarantine_email(server, message_id)
    except TransportError as exc:
        await log_server_event(db, server.id, "error", f"Quarantine failed: {exc}")
        await db.commit()
        raise ValidationError(str(exc))
    await log_server_event(db, server.id, "quarantine", f"Quarantined message {message_id}",
                           {"message_id": message_id, **detail})
    await db.commit()
    return {"status": "quarantined", "message_id": message_id, "detail": detail}


@router.get("/{org_id}/mail-servers/{server_id}/logs", response_model=list[MailServerLogResponse])
async def list_mail_server_logs(
    org_id: str,
    server_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    log_type: str | None = Query(default=None),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """This server's OWN log stream (grouped by server, never combined)."""
    server = await _get_server(db, org_id, server_id)
    predicates = [OrgMailServerLog.mail_server_id == server.id]
    if log_type:
        if log_type not in {"connection", "scan", "quarantine", "error"}:
            raise ValidationError("invalid log_type filter")
        predicates.append(OrgMailServerLog.log_type == log_type)
    for field, value, bound in (("from", from_date, lambda d: OrgMailServerLog.created_at >= d),
                                ("to", to_date, lambda d: OrgMailServerLog.created_at <= d)):
        if value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValidationError(f"Invalid {field}_date (expected ISO-8601)") from exc
            predicates.append(bound(parsed))

    result = await db.execute(
        select(OrgMailServerLog)
        .where(*predicates)
        .order_by(OrgMailServerLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [
        MailServerLogResponse(
            id=log.id,
            mail_server_id=log.mail_server_id,
            log_type=log.log_type,
            message=log.message,
            metadata=log.metadata_json,
            created_at=log.created_at,
        )
        for log in result.scalars().all()
    ]


@router.get("/{org_id}/mail-servers/{server_id}/settings", response_model=MailServerSettingsResponse)
async def get_mail_server_settings(
    org_id: str,
    server_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Per-server settings: analysts read; viewers are blocked (RLS + API)."""
    server = await _get_server(db, org_id, server_id)
    result = await db.execute(
        select(OrgMailServerSetting).where(OrgMailServerSetting.mail_server_id == server.id)
    )
    settings = {s.key: s.value.get("value") for s in result.scalars().all()}
    return MailServerSettingsResponse(mail_server_id=server.id, settings=settings)


@router.put("/{org_id}/mail-servers/{server_id}/settings", response_model=MailServerSettingsResponse)
async def update_mail_server_settings(
    org_id: str,
    server_id: str,
    payload: MailServerSettingsUpdate,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    if not isinstance(payload.settings, dict) or not payload.settings:
        raise ValidationError("settings must be a non-empty object")
    server = await _get_server(db, org_id, server_id)
    known = set(DEFAULT_SETTINGS.keys())
    for key, value in payload.settings.items():
        if key not in known:
            raise ValidationError(f"Unknown setting: {key} (valid: {sorted(known)})")
        result = await db.execute(
            select(OrgMailServerSetting).where(
                OrgMailServerSetting.mail_server_id == server.id,
                OrgMailServerSetting.key == key,
            )
        )
        setting = result.scalar_one_or_none()
        if setting is None:
            db.add(OrgMailServerSetting(
                mail_server_id=server.id, key=key, value={"value": value},
                updated_by=user.id,
            ))
        else:
            setting.value = {"value": value}
            setting.updated_by = user.id

    await log_server_event(db, server.id, "connection", f"Settings updated: {', '.join(payload.settings.keys())}")
    await db.commit()

    result = await db.execute(
        select(OrgMailServerSetting).where(OrgMailServerSetting.mail_server_id == server.id)
    )
    settings = {s.key: s.value.get("value") for s in result.scalars().all()}
    return MailServerSettingsResponse(mail_server_id=server.id, settings=settings)
