"""Regression: media analysis must stamp owner_user_id on created rows.

The live-Supabase RLS policy on cyberguard.events requires
``owner_user_id = current_setting('app.user_id')::text``; a NULL owner makes
the INSERT fail (NULL never matches). SQLite cannot enforce RLS, so this test
asserts the stamping directly on the created rows via the HTTP path.
"""

import io

import pytest
from PIL import Image
from sqlalchemy import select

from app.db.models import Event, MediaFile
from app.db.session import async_session_maker

pytestmark = [pytest.mark.http, pytest.mark.media]


@pytest.mark.http
@pytest.mark.media
async def test_media_analysis_stamps_owner(client):
    """POST /api/v1/analysis/media creates Event + MediaFile with the
    authenticated user's owner_user_id (RLS-safe)."""
    image = Image.new("RGB", (64, 64), color=(120, 40, 40))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)

    response = await client.post(
        "/api/v1/analysis/media",
        files={"file": ("rls_check.png", buffer.getvalue(), "image/png")},
    )
    assert response.status_code == 200, f"media analysis failed: {response.status_code} {response.text[:200]}"
    data = response.json()
    assert "authenticity_score" in data and "severity" in data

    event_id = data.get("event_id")
    assert event_id, "media analysis response must include the event_id"

    async with async_session_maker() as db:
        event = (
            await db.execute(select(Event).where(Event.id == event_id))
        ).scalar_one_or_none()
        assert event is not None, "Event row was created"
        assert event.owner_user_id is not None, (
            "Event.owner_user_id must be stamped (NULL violates the RLS policy on PostgreSQL)"
        )
        assert event.created_by == event.owner_user_id, (
            "created_by must be the authenticated user, not a hardcoded value"
        )
        media = (
            await db.execute(select(MediaFile).where(MediaFile.event_id == event_id))
        ).scalars().first()
        assert media is not None and media.owner_user_id == event.owner_user_id, (
            "MediaFile must carry the same owner_user_id"
        )
