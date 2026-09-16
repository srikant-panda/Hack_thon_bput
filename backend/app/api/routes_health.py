"""Health, readiness, and metrics endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import PlainTextResponse
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    """Liveness probe: fast process liveness check."""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready")
async def readiness_check(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Readiness probe: verifies Postgres and Redis connectivity."""
    settings = get_settings()
    now_str = datetime.now(timezone.utc).isoformat()
    postgres_ok = False
    redis_ok = False
    details: dict[str, str] = {}

    # 1. Postgres connectivity check (simple SELECT 1)
    try:
        await db.execute(text("SELECT 1"))
        postgres_ok = True
        details["postgres"] = "ok"
    except Exception as exc:
        postgres_ok = False
        details["postgres"] = f"error: {str(exc)}"

    # 2. Redis connectivity check (ping)
    try:
        r = Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2.0)
        pong = await r.ping()
        await r.aclose()
        if pong:
            redis_ok = True
            details["redis"] = "ok"
        else:
            redis_ok = False
            details["redis"] = "ping_failed"
    except Exception as exc:
        redis_ok = False
        details["redis"] = f"error: {str(exc)}"

    if not (postgres_ok and redis_ok):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "unavailable",
            "ready": False,
            "timestamp": now_str,
            "details": details,
        }

    return {
        "status": "ok",
        "ready": True,
        "timestamp": now_str,
        "details": details,
    }


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> PlainTextResponse:
    """Return real-time Prometheus-formatted metrics."""
    from app.core.metrics import generate_prometheus_metrics, update_queue_depth

    try:
        await update_queue_depth()
    except Exception:
        pass

    content = generate_prometheus_metrics()
    return PlainTextResponse(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")
