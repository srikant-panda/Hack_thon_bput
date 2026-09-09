"""SOC assistant chat endpoints using Async SQLAlchemy."""

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext, require_role
from app.db.session import get_db
from app.schemas.assistant import AssistantChatRequest, AssistantChatResponse
from app.services import assistant_service

router = APIRouter(prefix="/assistant", tags=["SOC Assistant"])


@router.post("/chat", response_model=AssistantChatResponse)
async def chat_with_assistant(
    payload: AssistantChatRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict[str, Any]:
    """Answer analyst questions grounded in recent organizational alert context."""
    return await assistant_service.chat_with_assistant(
        db,
        organization_id=tenant.organization_id,
        user_message=payload.message,
        user_id=tenant.user_id,
        user_name=tenant.user_email or tenant.user_id,
    )
