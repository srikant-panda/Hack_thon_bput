"""Reconciliation service for catching dropped Pub/Sub notifications and recovering stuck accounts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import GmailAccount
from app.queue.client import enqueue
from app.services.idempotency_service import ensure_job
from app.workers.base import get_db_session

logger = logging.getLogger("cyberguard.gmail.reconciliation")


async def _run_reconcile_stuck_accounts(
    db: AsyncSession,
    account_ids: Optional[list[str]] = None,
    owner_user_id: Optional[str] = None,
) -> dict[str, Any]:
    """Internal implementation of reconciliation on an open database session."""
    now = datetime.now(timezone.utc)
    two_hours_ago = now - timedelta(hours=2)

    # Condition 1: Active accounts that haven't synced in >2 hours (or never synced)
    cond_active = (GmailAccount.sync_status == "active") & (
        (GmailAccount.last_sync_at < two_hours_ago)
        | (GmailAccount.last_sync_at.is_(None))
    )

    # Condition 2: Accounts in error status with transient errors (NOT reauth_required or scope_error)
    cond_transient_error = (GmailAccount.sync_status == "error") & (
        (GmailAccount.last_error.is_(None))
        | (~GmailAccount.last_error.in_(["reauth_required", "scope_error"]))
    )

    stmt = select(GmailAccount).where(cond_active | cond_transient_error)
    if account_ids is not None:
        stmt = stmt.where(GmailAccount.id.in_(account_ids))
    if owner_user_id is not None:
        stmt = stmt.where(GmailAccount.owner_user_id == owner_user_id)
    accounts = (await db.execute(stmt)).scalars().all()

    enqueued_count = 0
    enqueued_account_ids: list[str] = []

    for account in accounts:
        reconcile_job_id = f"gmail_sync:{account.owner_user_id}:reconciliation"
        payload = {
            "account_id": str(account.id),
            "history_id": account.last_history_id or "0",
        }

        # 1. Idempotently record job in DB job_queue ledger
        await ensure_job(
            db,
            owner_user_id=account.owner_user_id,
            job_type="gmail_sync",
            job_id=reconcile_job_id,
            payload=payload,
        )

        # 2. Enqueue to Redis queue with deterministic job_id
        try:
            await enqueue(
                "gmail_sync",
                kwargs=payload,
                job_id=reconcile_job_id,
            )
        except Exception as exc:
            logger.warning(
                "Failed to enqueue reconciliation job %s to Redis for account %s: %s",
                reconcile_job_id,
                account.id,
                exc,
            )

        enqueued_count += 1
        enqueued_account_ids.append(str(account.id))

    await db.commit()

    logger.info(
        "Reconciliation completed: %d accounts evaluated/enqueued",
        len(accounts),
    )
    return {
        "total_evaluated": len(accounts),
        "enqueued": enqueued_count,
        "reconciled_account_ids": enqueued_account_ids,
    }


async def reconcile_stuck_accounts(
    db_or_ctx: Any = None,
    account_ids: Optional[list[str]] = None,
    owner_user_id: Optional[str] = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Reconcile stuck Gmail accounts and trigger sync jobs.

    Accepts an AsyncSession (testing), an Arq worker ctx dict, or None (opens session).
    """
    if hasattr(db_or_ctx, "execute"):
        return await _run_reconcile_stuck_accounts(
            db_or_ctx, account_ids=account_ids, owner_user_id=owner_user_id
        )

    if isinstance(db_or_ctx, dict):
        async with get_db_session(db_or_ctx) as db:
            return await _run_reconcile_stuck_accounts(
                db, account_ids=account_ids, owner_user_id=owner_user_id
            )

    from app.db.session import async_session_maker

    async with async_session_maker() as db:
        return await _run_reconcile_stuck_accounts(
            db, account_ids=account_ids, owner_user_id=owner_user_id
        )
