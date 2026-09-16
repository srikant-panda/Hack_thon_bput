"""Gmail account service for managing connected accounts, tokens, and history checkpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import GmailAccount


async def get_or_create_gmail_account(
    db: AsyncSession,
    owner_user_id: str,
    email: str,
    access_token: Optional[str],
    refresh_token: str,
) -> GmailAccount:
    """Lookup or create a GmailAccount with encrypted tokens.

    1. Lookup by (owner_user_id, email).
    2. If exists: update encrypted tokens and return.
    3. If not exists: create with encrypted tokens, last_history_id=None, watch_expiration=None.
    """
    stmt = select(GmailAccount).where(
        GmailAccount.owner_user_id == owner_user_id,
        GmailAccount.email == email,
    )
    account = (await db.execute(stmt)).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if account is not None:
        account.set_access_token(access_token)
        account.set_refresh_token(refresh_token)
        account.updated_at = now
        await db.commit()
        await db.refresh(account)
        return account

    account = GmailAccount(
        owner_user_id=owner_user_id,
        email=email,
        sync_status="active",
        last_history_id=None,
        watch_expiration=None,
        created_at=now,
        updated_at=now,
    )
    account.set_access_token(access_token)
    account.set_refresh_token(refresh_token)
    db.add(account)
    await db.commit()
    await db.refresh(account)
    return account


def is_greater_history_id(new_id: Optional[str], old_id: Optional[str]) -> bool:
    """Compare two history IDs, treating them as integers when numeric."""
    if new_id is None:
        return False
    if old_id is None:
        return True
    try:
        return int(new_id) > int(old_id)
    except (ValueError, TypeError):
        return str(new_id) > str(old_id)


async def update_history_id(
    db: AsyncSession,
    gmail_account_id: str,
    new_history_id: str,
) -> GmailAccount:
    """Update last_history_id using a SELECT ... FOR UPDATE row lock to serialize concurrent updates.

    Only updates last_history_id if new_history_id > current last_history_id.
    """
    stmt = (
        select(GmailAccount)
        .where(GmailAccount.id == gmail_account_id)
        .with_for_update()
    )
    account = (await db.execute(stmt)).scalar_one()
    now = datetime.now(timezone.utc)
    if is_greater_history_id(new_history_id, account.last_history_id):
        account.last_history_id = str(new_history_id)
    account.last_sync_at = now
    account.updated_at = now
    await db.commit()
    await db.refresh(account)
    return account


async def update_watch_expiration(
    db: AsyncSession,
    gmail_account_id: str,
    expiration: datetime,
) -> GmailAccount:
    """Update watch_expiration timestamp for Pub/Sub push subscription."""
    stmt = select(GmailAccount).where(GmailAccount.id == gmail_account_id)
    account = (await db.execute(stmt)).scalar_one()
    account.watch_expiration = expiration
    account.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(account)
    return account
