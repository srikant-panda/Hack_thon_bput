"""Database introspection endpoints using Async SQLAlchemy."""

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import CurrentUser, get_current_user
from app.db.models import Alert, AuditLog, Event, Incident, Organization, ResponseExecution, User
from app.db.session import get_db

router = APIRouter(tags=["db"])

MODEL_MAP = {
    "users": User,
    "organizations": Organization,
    "events": Event,
    "alerts": Alert,
    "incidents": Incident,
    "response_executions": ResponseExecution,
    "audit_logs": AuditLog,
}


@router.get("/db/check")
async def check_database(
    _user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return row counts for core tables using Async SQLAlchemy."""
    counts: dict[str, int | None] = {}
    errors: dict[str, str] = {}

    for name, model in MODEL_MAP.items():
        try:
            res = await db.execute(select(func.count()).select_from(model))
            counts[name] = res.scalar() or 0
        except Exception as exc:
            counts[name] = None
            errors[name] = str(exc)

    payload: dict = {"tables": counts}
    if errors:
        payload["errors"] = errors
    return payload
