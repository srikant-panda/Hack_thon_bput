"""Supabase and local fallback Storage integration for media uploads (Part 2).

All uploads use the service role client. The 'cyberguard-media' bucket is
private; read access is granted through short-lived signed URLs.
If Supabase storage is unavailable, it falls back to local disk storage
so that media forensics analysis never fails with a 500 error.
"""

import logging
from pathlib import Path, PurePosixPath

from fastapi import HTTPException, UploadFile, status
from supabase import Client

from app.core.supabase_client import get_supabase

logger = logging.getLogger("cyberguard.storage")

MEDIA_BUCKET = "cyberguard-media"
MAX_MEDIA_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB
SIGNED_URL_EXPIRY_SECONDS = 3600  # 1 hour
LOCAL_STORAGE_DIR = Path("./storage/media")


def _sanitize_file_name(file_name: str | None) -> str:
    """Strip any path components from the client-supplied file name."""
    if not file_name:
        return "upload.bin"
    return PurePosixPath(file_name.replace("\\", "/")).name or "upload.bin"


def _ensure_bucket_exists(client: Client) -> None:
    """Verify the media bucket exists or create it if missing."""
    try:
        buckets = client.storage.list_buckets()
        names = [
            b.name if hasattr(b, "name") else (b.get("name") if isinstance(b, dict) else "")
            for b in buckets
        ]
        if MEDIA_BUCKET not in names:
            logger.info("Bucket '%s' not found in Supabase. Creating private bucket...", MEDIA_BUCKET)
            client.storage.create_bucket(MEDIA_BUCKET, options={"public": False})
    except Exception as exc:
        logger.warning("Could not verify or create Supabase bucket '%s': %s", MEDIA_BUCKET, exc)


def upload_media_to_supabase(
    file: UploadFile,
    event_id: str,
    content_bytes: bytes | None = None,
) -> dict:
    """Upload a media file to Supabase Storage with local fallback.

    Returns a dict with file_name, storage_path, file_type and size_bytes.
    Raises HTTPException 413 if the file exceeds the 25 MB limit.
    """
    if content_bytes is None:
        file.file.seek(0)
        content = file.file.read()
        file.file.seek(0)
    else:
        content = content_bytes

    if len(content) > MAX_MEDIA_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds maximum allowed size of 25 MB",
        )

    file_name = _sanitize_file_name(file.filename)
    storage_path = f"media/{event_id}/{file_name}"

    # 1. Attempt Supabase upload
    supabase_success = False
    try:
        client: Client = get_supabase()
        _ensure_bucket_exists(client)
        client.storage.from_(MEDIA_BUCKET).upload(
            path=storage_path,
            file=content,
            file_options={
                "content-type": file.content_type or "application/octet-stream",
                "upsert": "true",
            },
        )
        supabase_success = True
        logger.info("Successfully uploaded %s to Supabase storage (%s)", file_name, storage_path)
    except Exception as exc:
        logger.warning(
            "Supabase media storage upload failed for %s (%s). Engaging local storage fallback.",
            file_name,
            exc,
        )

    # 2. If Supabase failed, persist to local storage folder so analysis succeeds
    if not supabase_success:
        try:
            local_dest = LOCAL_STORAGE_DIR / event_id / file_name
            local_dest.parent.mkdir(parents=True, exist_ok=True)
            local_dest.write_bytes(content)
            storage_path = str(local_dest)
            logger.info("Saved %s to local storage fallback (%s)", file_name, storage_path)
        except Exception as local_err:
            logger.error("Local storage fallback also failed: %s", local_err)

    return {
        "file_name": file_name,
        "storage_path": storage_path,
        "file_type": file.content_type,
        "size_bytes": len(content),
    }


def create_media_signed_url(storage_path: str) -> str:
    """Return a temporary signed URL (valid 1 hour) for a stored media file."""
    # If local path fallback, return direct API endpoint
    if storage_path.startswith("storage/") or "/" in storage_path and Path(storage_path).exists():
        return f"/api/v1/media/file/{storage_path}"

    try:
        client: Client = get_supabase()
        result = client.storage.from_(MEDIA_BUCKET).create_signed_url(
            storage_path, SIGNED_URL_EXPIRY_SECONDS
        )
        signed_url = (
            result.get("signedURL") or result.get("signedUrl")
            if isinstance(result, dict)
            else (getattr(result, "signed_url", None) or str(result))
        )
        if signed_url:
            return signed_url
    except Exception as exc:
        logger.warning("Failed to create Supabase signed URL for %s: %s", storage_path, exc)

    return f"/api/v1/media/file/{storage_path}"


def download_media(storage_path: str) -> bytes:
    """Download a stored media file's bytes using Supabase or local storage."""
    local_path = Path(storage_path)
    if local_path.exists():
        return local_path.read_bytes()

    try:
        client: Client = get_supabase()
        return client.storage.from_(MEDIA_BUCKET).download(storage_path)
    except Exception as exc:
        logger.warning("Supabase storage download failed for %s: %s", storage_path, exc)
        if local_path.exists():
            return local_path.read_bytes()
        raise
