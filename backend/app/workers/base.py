"""Base worker classes, settings, and context helpers for Arq workers."""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any, Optional

from arq.connections import RedisSettings

from app.core.config import get_settings
from app.core.logging_config import (
    SensitiveDataFilter,
    StructuredJsonFormatter,
    clear_log_context,
    current_correlation_id,
    set_log_context,
)

# Alias for backward compatibility
JsonFormatter = StructuredJsonFormatter


def get_worker_logger(name: str = "cyberguard.worker") -> logging.Logger:
    """Return configured structured logger for background workers."""
    logger = logging.getLogger(name)
    if not any(isinstance(h.formatter, StructuredJsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJsonFormatter())
        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def log_worker_event(
    logger: logging.Logger,
    level: int,
    message: str,
    *,
    correlation_id: str | None = None,
    job_id: str | None = None,
    job_type: str | None = None,
    user_id: str | None = None,
    worker_name: str | None = None,
    **extra: Any,
) -> None:
    """Log an event with standard worker structured metadata."""
    corr = correlation_id or current_correlation_id.get()
    record_extra = {
        "correlation_id": corr,
        "job_id": job_id,
        "job_type": job_type,
        "user_id": user_id,
        "worker_name": worker_name,
        **extra,
    }
    logger.log(level, message, extra=record_extra)


@asynccontextmanager
async def job_context(
    ctx: Optional[dict[str, Any]] = None,
    job_type: Optional[str] = None,
    job_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    user_id: Optional[str] = None,
    worker_name: Optional[str] = None,
):
    """Context manager binding correlation ID and worker metadata to contextvars during execution."""
    ctx_dict = ctx if isinstance(ctx, dict) else {}
    corr_id = correlation_id or ctx_dict.get("job_id") or job_id or str(uuid.uuid4())
    j_id = job_id or ctx_dict.get("job_id") or corr_id
    set_log_context(
        correlation_id=corr_id,
        job_id=j_id,
        job_type=job_type,
        user_id=user_id,
        worker_name=worker_name,
    )
    try:
        yield corr_id
        if worker_name:
            try:
                from app.core.metrics import worker_jobs_total
                worker_jobs_total.labels(
                    worker_name=worker_name,
                    job_type=job_type or "unknown",
                    status="success",
                ).inc()
            except Exception:
                pass
    except Exception:
        if worker_name:
            try:
                from app.core.metrics import worker_jobs_total
                worker_jobs_total.labels(
                    worker_name=worker_name,
                    job_type=job_type or "unknown",
                    status="failed",
                ).inc()
            except Exception:
                pass
        raise
    finally:
        clear_log_context()


@asynccontextmanager
async def get_db_session(ctx: dict[str, Any]):
    """Context helper providing an async SQLAlchemy session from Arq ctx."""
    db = ctx.get("db")
    if db is not None:
        yield db
        return

    db_maker = ctx.get("db_maker")
    if db_maker is None:
        from app.db.admin import _get_admin_session_maker
        db_maker = _get_admin_session_maker()

    async with db_maker() as session:
        yield session


async def base_startup(ctx: dict[str, Any]) -> None:
    """Initialize resources on worker startup."""
    from app.db.admin import _get_admin_session_maker

    ctx["db_maker"] = _get_admin_session_maker()
    logger = get_worker_logger("cyberguard.worker")
    ctx["logger"] = logger
    log_worker_event(logger, logging.INFO, "Worker process started", job_type="lifecycle")


async def base_shutdown(ctx: dict[str, Any]) -> None:
    """Clean up resources on worker graceful shutdown."""
    logger = ctx.get("logger") or get_worker_logger("cyberguard.worker")
    log_worker_event(logger, logging.INFO, "Worker process shutting down gracefully", job_type="lifecycle")


class WorkerSettings:
    """Base WorkerSettings for CYBERGUARD Arq background workers."""

    _settings = get_settings()

    redis_settings: RedisSettings = RedisSettings.from_dsn(_settings.REDIS_URL)
    queue_name: str = _settings.ARQ_QUEUE_NAME
    max_jobs: int = _settings.ARQ_MAX_JOBS
    job_timeout: int = _settings.ARQ_JOB_TIMEOUT
    retry_jobs: bool = True
    max_tries: int = 3
    functions: list[Any] = []
    cron_jobs: list[Any] = []

    on_startup = base_startup
    on_shutdown = base_shutdown

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        base_attrs = [
            "redis_settings",
            "queue_name",
            "max_jobs",
            "job_timeout",
            "retry_jobs",
            "max_tries",
            "on_startup",
            "on_shutdown",
        ]
        for attr in base_attrs:
            if attr not in cls.__dict__ and hasattr(WorkerSettings, attr):
                setattr(cls, attr, getattr(WorkerSettings, attr))
