"""Event email notification endpoints (Phase 7).

The log is strictly owner-scoped; recipients are always the user's registered
notification_email — never a connected mailbox.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.services.notification_service import list_logs, serialize_log

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("")
async def list_notification_logs(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
) -> dict:
    logs = await list_logs(db, user.id, limit=min(limit, 200))
    return {"items": [serialize_log(l) for l in logs]}
