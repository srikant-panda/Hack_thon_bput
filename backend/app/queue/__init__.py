"""Queue package for CYBERGUARD real-time asynchronous background pipelines."""

from app.queue.client import (
    QueueClient,
    close_redis_pool,
    create_redis_pool,
    enqueue,
    get_queue,
    make_email_scan_job_id,
    make_gmail_sync_job_id,
)

__all__ = [
    "QueueClient",
    "create_redis_pool",
    "close_redis_pool",
    "get_queue",
    "enqueue",
    "make_gmail_sync_job_id",
    "make_email_scan_job_id",
]
