"""Gmail worker for asynchronous mailbox sync and real-time ingestion."""

from __future__ import annotations

from typing import Any

from app.workers.base import WorkerSettings as BaseWorkerSettings


class WorkerSettings(BaseWorkerSettings):
    """Worker settings for Gmail real-time ingestion and synchronization.

    Job functions list is populated in RT-4.
    """

    functions: list[Any] = []
