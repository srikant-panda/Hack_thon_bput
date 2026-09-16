"""Queue client and helpers for Arq and Redis-backed asynchronous pipelines."""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Any

from arq.connections import ArqRedis, RedisSettings
from arq.connections import create_pool as arq_create_pool
from arq.jobs import Job, JobDef

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.queue")

_redis_pool: ArqRedis | None = None


def make_gmail_sync_job_id(user_id: str, history_id: str | int) -> str:
    """Generate deterministic job ID for Gmail sync operations."""
    return f"gmail_sync:{user_id}:{history_id}"


def make_email_scan_job_id(user_id: str, message_id: str) -> str:
    """Generate deterministic job ID for email scan operations."""
    return f"email_scan:{user_id}:{message_id}"


async def create_redis_pool(redis_url: str | None = None) -> ArqRedis:
    """Create an ArqRedis connection pool connected to Redis."""
    settings = get_settings()
    url = redis_url or settings.REDIS_URL
    redis_settings = RedisSettings.from_dsn(url)
    return await arq_create_pool(redis_settings, default_queue_name=settings.ARQ_QUEUE_NAME)


async def close_redis_pool() -> None:
    """Close active global redis pool."""
    global _redis_pool
    if _redis_pool is not None:
        try:
            await _redis_pool.aclose()
        except Exception:
            pass
        _redis_pool = None


class QueueClient:
    """Wrapper around arq.ArqRedis with enqueue_job() and job_info() helpers."""

    def __init__(self, pool: ArqRedis):
        self.pool = pool

    async def enqueue_job(
        self,
        function: str,
        *args: Any,
        _job_id: str | None = None,
        _queue_name: str | None = None,
        _defer_by: int | float | timedelta | None = None,
        **kwargs: Any,
    ) -> Job | None:
        """Enqueue job with idempotency.

        If a job with _job_id already exists in Redis, returns the existing Job instance.
        """
        target_queue = _queue_name or self.pool.default_queue_name
        job = await self.pool.enqueue_job(
            function,
            *args,
            _job_id=_job_id,
            _queue_name=target_queue,
            _defer_by=_defer_by,
            **kwargs,
        )
        if job is None and _job_id:
            # Idempotent: return existing Job object
            return Job(_job_id, redis=self.pool, _queue_name=target_queue)
        return job

    async def job_info(self, job_id: str) -> JobDef | None:
        """Fetch JobDef info for a given job_id."""
        job = Job(job_id, redis=self.pool, _queue_name=self.pool.default_queue_name)
        return await job.info()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.pool, name)


async def get_queue(redis_url: str | None = None) -> QueueClient:
    """Get or initialize singleton QueueClient wrapper around ArqRedis."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = await create_redis_pool(redis_url)
    return QueueClient(_redis_pool)


async def enqueue(
    job_type: str,
    kwargs: dict[str, Any] | None = None,
    queue_name: str | None = None,
    job_id: str | None = None,
    defer_by: int | float | timedelta | None = None,
) -> str:
    """Helper to enqueue a job and return its job_id."""
    settings = get_settings()
    target_queue = queue_name or settings.ARQ_QUEUE_NAME
    target_job_id = job_id or str(uuid.uuid4())
    payload = kwargs if kwargs is not None else {}

    queue = await get_queue()
    job = await queue.enqueue_job(
        job_type,
        _job_id=target_job_id,
        _queue_name=target_queue,
        _defer_by=defer_by,
        **payload,
    )
    if job is None:
        return target_job_id
    return job.job_id
