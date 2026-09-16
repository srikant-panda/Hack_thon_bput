"""Job state machine service for real-time processing pipeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import JobQueue

# Backoff schedule: 5s, 30s, 2min (120s), 10min (600s), 30min (1800s)
BACKOFF_DELAYS_SECONDS = [5, 30, 120, 600, 1800]


def compute_backoff_delay(retry_count: int) -> int:
    """Return exponential backoff delay in seconds for given 1-based retry count."""
    if retry_count <= 0:
        return BACKOFF_DELAYS_SECONDS[0]
    idx = min(retry_count - 1, len(BACKOFF_DELAYS_SECONDS) - 1)
    return BACKOFF_DELAYS_SECONDS[idx]


async def update_job_status(
    db: AsyncSession,
    job_id: str,
    new_status: str,
    result: Optional[dict[str, Any]] = None,
    error: Optional[str] = None,
) -> JobQueue:
    """Update job queue status with state machine enforcement and backoff schedule.

    State transitions:
    - queued -> running
    - running -> completed
    - running -> failed (retry_count < max_retries)
    - running -> dead_letter (retry_count >= max_retries)
    - failed -> queued (retry_count < max_retries)
    - failed -> dead_letter (retry_count >= max_retries)
    """
    stmt = select(JobQueue).where(JobQueue.job_id == job_id)
    job = (await db.execute(stmt)).scalar_one_or_none()
    if job is None:
        raise ValueError(f"Job not found: {job_id}")

    # Validate transition against current state
    if not JobQueue.can_transition(job.status, new_status, job.retry_count, job.max_retries):
        raise ValueError(
            f"Invalid transition from {job.status} to {new_status} "
            f"(retry_count={job.retry_count}, max_retries={job.max_retries})"
        )

    now = datetime.now(timezone.utc)

    if new_status == "running":
        job.started_at = now
    elif new_status == "completed":
        job.completed_at = now

    # On failure or error
    if error is not None or new_status in ("failed", "dead_letter"):
        job.error = error or job.error
        job.retry_count += 1
        if new_status == "dead_letter":
            job.next_retry_at = None
        else:
            delay = compute_backoff_delay(job.retry_count)
            job.next_retry_at = now + timedelta(seconds=delay)

    if result is not None:
        job.result = result

    job.status = new_status
    job.updated_at = now

    await db.commit()
    await db.refresh(job)
    return job
