"""Health check endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.supabase_client import check_connection
from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
async def read_health(db: AsyncSession = Depends(get_db)) -> dict:
    """Public liveness and readiness probe with database connectivity check."""
    settings = get_settings()

    db_connected = False
    try:
        await db.execute(text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    return {
        "status": "ok" if db_connected else "degraded",
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database_connected": db_connected,
        "supabase_connected": check_connection(),
    }
