"""Multi-source event ingestion endpoints using Async SQLAlchemy."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ValidationError
from app.core.security import TenantContext, require_role, tenant_criteria
from app.core.storage import (
    MAX_MEDIA_SIZE_BYTES,
    SIGNED_URL_EXPIRY_SECONDS,
    create_media_signed_url,
    upload_media_to_supabase,
)
from app.db.models import Event, MediaFile
from app.db.session import get_db
from app.schemas.events import (
    ApiLogEvent,
    AuthLogEvent,
    EmailEvent,
    MessageEvent,
    NetworkFlowEvent,
    UrlEvent,
)

router = APIRouter(prefix="/events", tags=["Events"])

MEDIA_CONTENT_TYPE_PREFIXES = ("image/", "audio/", "video/")
MEDIA_SOURCE = "media_upload"


async def _insert_event(
    db: AsyncSession,
    *,
    tenant: TenantContext,
    created_by: str,
    event_type: str,
    source: str,
    raw_data: dict,
) -> str:
    """Insert a new event row with status 'received' and return its id."""
    event_id = str(uuid.uuid4())
    event = Event(
        id=event_id,
        organization_id=tenant.organization_id,
        owner_user_id=tenant.owner_user_id,
        event_type=event_type,
        source=source,
        raw_data=raw_data,
        status="received",
        created_by=created_by,
    )
    db.add(event)
    await db.commit()
    return event_id


async def _ingest_payload(
    payload: BaseModel,
    db: AsyncSession,
    tenant: TenantContext,
) -> dict:
    """Persist a validated payload as a raw event and return the response."""
    event_id = await _insert_event(
        db,
        tenant=tenant,
        created_by=tenant.user_id,
        event_type=payload.event_type,
        source=payload.source,
        raw_data=payload.model_dump(mode="json"),
    )
    return {"event_id": event_id, "event_type": payload.event_type, "status": "received"}


@router.post("/email")
async def ingest_email_event(
    payload: EmailEvent,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    return await _ingest_payload(payload, db, tenant)


@router.post("/url")
async def ingest_url_event(
    payload: UrlEvent,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    return await _ingest_payload(payload, db, tenant)


@router.post("/message")
async def ingest_message_event(
    payload: MessageEvent,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    return await _ingest_payload(payload, db, tenant)


@router.post("/auth-log")
async def ingest_auth_log_event(
    payload: AuthLogEvent,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    return await _ingest_payload(payload, db, tenant)


@router.post("/network")
async def ingest_network_flow_event(
    payload: NetworkFlowEvent,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    return await _ingest_payload(payload, db, tenant)


@router.post("/api-log")
async def ingest_api_log_event(
    payload: ApiLogEvent,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    return await _ingest_payload(payload, db, tenant)


@router.post("/media")
async def ingest_media_event(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """Upload image/audio/video media and register it as a deepfake_media event."""
    content_type = file.content_type or ""
    if not content_type.startswith(MEDIA_CONTENT_TYPE_PREFIXES):
        raise ValidationError("File must be an image, audio, or video upload")

    event_id = str(uuid.uuid4())
    event = Event(
        id=event_id,
        organization_id=tenant.organization_id,
        owner_user_id=tenant.owner_user_id,
        event_type="deepfake_media",
        source=MEDIA_SOURCE,
        raw_data={
            "event_id": event_id,
            "file_name": file.filename,
            "content_type": content_type,
        },
        status="received",
        created_by=tenant.user_id,
    )
    db.add(event)
    await db.flush()

    try:
        media_record = upload_media_to_supabase(file, event_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload media file to storage: {exc}",
        ) from exc

    media_entry = MediaFile(
        id=str(uuid.uuid4()),
        event_id=event_id,
        owner_user_id=tenant.owner_user_id,
        file_name=media_record["file_name"],
        storage_path=media_record["storage_path"],
        file_type=media_record["file_type"],
        size_bytes=media_record["size_bytes"],
    )
    db.add(media_entry)
    await db.commit()

    return {
        "event_id": event_id,
        "event_type": "deepfake_media",
        "file_name": media_record["file_name"],
        "storage_path": media_record["storage_path"],
        "file_type": media_record["file_type"],
        "size_bytes": media_record["size_bytes"],
        "status": "received",
    }


@router.get("/media/{event_id}/url")
async def get_media_url(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> dict:
    """Return a 1-hour signed download URL for the media file associated with an event."""
    from sqlalchemy import select
    from app.core.errors import NotFoundError

    query = (
        select(MediaFile)
        .join(Event, Event.id == MediaFile.event_id)
        .where(MediaFile.event_id == event_id, tenant_criteria(MediaFile, tenant))
    )
    result = await db.execute(query)
    media_file = result.scalar_one_or_none()
    if media_file is None:
        raise NotFoundError("Media file for event", event_id)

    signed_url = create_media_signed_url(media_file.storage_path)
    return {
        "event_id": event_id,
        "file_name": media_file.file_name,
        "signed_url": signed_url,
        "expires_in_seconds": SIGNED_URL_EXPIRY_SECONDS,
    }
