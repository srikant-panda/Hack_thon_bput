"""Email worker for asynchronous email analysis, heuristics, ML scoring, and enforcement."""

from __future__ import annotations

from typing import Any

from app.workers.base import WorkerSettings as BaseWorkerSettings


class WorkerSettings(BaseWorkerSettings):
    """Worker settings for general email analysis and autonomous SOAR enforcement.

    Job functions list is populated in RT-5/6.
    """

    functions: list[Any] = []
