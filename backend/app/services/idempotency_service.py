"""Idempotency helpers for real-time pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import JobQueue, ProcessedEmail


async def ensure_processed_email(
    db: AsyncSession,
    owner_user_id: str,
    gmail_message_id: str,
    gmail_account_id: str,
    received_at: Optional[datetime] = None,
    subject: Optional[str] = None,
    sender: Optional[str] = None,
) -> ProcessedEmail:
    """Ensure a processed_emails record exists idempotently.

    1. Attempts insertion with unique constraint (owner_user_id, gmail_message_id).
    2. On IntegrityError (duplicate message), returns existing row.
    3. Caller checks: if existing.processing_status == 'completed', skip processing.
    4. Returns new or existing row.
    """
    now = received_at or datetime.now(timezone.utc)
    try:
        async with db.begin_nested():
            email_record = ProcessedEmail(
                owner_user_id=owner_user_id,
                gmail_account_id=gmail_account_id,
                gmail_message_id=gmail_message_id,
                received_at=now,
                subject=subject,
                sender=sender,
                processing_status="received",
            )
            db.add(email_record)
            await db.flush()
        await db.commit()
        await db.refresh(email_record)
        return email_record
    except IntegrityError:
        stmt = select(ProcessedEmail).where(
            ProcessedEmail.owner_user_id == owner_user_id,
            ProcessedEmail.gmail_message_id == gmail_message_id,
        )
        existing = (await db.execute(stmt)).scalar_one_or_none()
        if existing is None:
            raise
        return existing


async def ensure_job(
    db: AsyncSession,
    owner_user_id: str,
    job_type: str,
    job_id: str,
    payload: Optional[dict[str, Any]] = None,
) -> JobQueue:
    """Ensure a job_queue record exists idempotently.

    1. Attempts insertion with unique job_id.
    2. On IntegrityError (duplicate job_id), returns existing row.
    3. Caller checks: if existing.status in ('completed', 'running'), skip enqueue.
    4. Returns new or existing row.
    """
    try:
        async with db.begin_nested():
            job = JobQueue(
                owner_user_id=owner_user_id,
                job_type=job_type,
                job_id=job_id,
                status="queued",
                payload=payload or {},
            )
            db.add(job)
            await db.flush()
        await db.commit()
        await db.refresh(job)
        return job
    except IntegrityError:
        stmt = select(JobQueue).where(JobQueue.job_id == job_id)
        existing = (await db.execute(stmt)).scalar_one_or_none()
        if existing is None:
            raise
        return existing
