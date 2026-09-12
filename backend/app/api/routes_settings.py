"""Per-connector enforcement settings (quarantine expiry, deletion, auto-quarantine)."""

import uuid
from typing import Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import CurrentUser, get_current_user
from app.db.models import ConnectorSettings
from app.db.session import get_db
from app.services.action_engine import get_or_create_settings
from app.services.connectors import connector_service

router = APIRouter(prefix="/connectors", tags=["Connector Settings"])


class ConnectorSettingsRead(BaseModel):
    connector_id: str
    quarantine_expiry_hours: Optional[int] = None
    permanent_delete_enabled: bool
    auto_quarantine_enabled: bool
    updated_at: Optional[str] = None


class ConnectorSettingsUpdate(BaseModel):
    quarantine_expiry_hours: Optional[int] = Field(default=None, ge=1, le=24 * 30)
    expiry_mode: Optional[Literal["hours", "manual"]] = None
    permanent_delete_enabled: Optional[bool] = None
    auto_quarantine_enabled: Optional[bool] = None


def _serialize(settings: ConnectorSettings) -> ConnectorSettingsRead:
    return ConnectorSettingsRead(
        connector_id=settings.connector_id,
        quarantine_expiry_hours=settings.quarantine_expiry_hours,
        permanent_delete_enabled=settings.permanent_delete_enabled,
        auto_quarantine_enabled=settings.auto_quarantine_enabled,
        updated_at=settings.updated_at.isoformat() if settings.updated_at else None,
    )


@router.get("/{connector_id}/settings", response_model=ConnectorSettingsRead)
async def get_settings(
    connector_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorSettingsRead:
    connector = await connector_service.get_connector(db, connector_id, user.id)
    if connector is None:
        from app.core.errors import NotFoundError

        raise NotFoundError("Email connector", connector_id)
    settings = await get_or_create_settings(db, connector)
    return _serialize(settings)


@router.put("/{connector_id}/settings", response_model=ConnectorSettingsRead)
async def update_settings(
    connector_id: str,
    payload: ConnectorSettingsUpdate,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorSettingsRead:
    from app.core.errors import NotFoundError

    connector = await connector_service.get_connector(db, connector_id, user.id)
    if connector is None:
        raise NotFoundError("Email connector", connector_id)
    settings = await get_or_create_settings(db, connector)

    if payload.expiry_mode == "manual":
        settings.quarantine_expiry_hours = None
    elif payload.expiry_mode == "hours":
        settings.quarantine_expiry_hours = payload.quarantine_expiry_hours or 24
    elif payload.quarantine_expiry_hours is not None:
        settings.quarantine_expiry_hours = payload.quarantine_expiry_hours

    if payload.permanent_delete_enabled is not None:
        settings.permanent_delete_enabled = payload.permanent_delete_enabled
    if payload.auto_quarantine_enabled is not None:
        settings.auto_quarantine_enabled = payload.auto_quarantine_enabled

    if settings.id is None:
        settings.id = str(uuid.uuid4())
    await db.commit()
    await db.refresh(settings)
    return _serialize(settings)
