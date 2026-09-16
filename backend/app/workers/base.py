"""Base worker classes, settings, and context helpers for Arq workers."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from arq.connections import RedisSettings

from app.core.config import get_settings


class JsonFormatter(logging.Formatter):
    """Structured JSON formatter for worker logs."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", None),
            "job_id": getattr(record, "job_id", None),
            "job_type": getattr(record, "job_type", None),
            "user_id": getattr(record, "user_id", None),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def get_worker_logger(name: str = "cyberguard.worker") -> logging.Logger:
    """Return configured structured logger for background workers."""
    logger = logging.getLogger(name)
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
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
    **extra: Any,
) -> None:
    """Log an event with standard worker structured metadata."""
    record_extra = {
        "correlation_id": correlation_id,
        "job_id": job_id,
        "job_type": job_type,
        "user_id": user_id,
        **extra,
    }
    logger.log(level, message, extra=record_extra)


@asynccontextmanager
async def get_db_session(ctx: dict[str, Any]):
    """Context helper providing an async SQLAlchemy session from Arq ctx."""
    db = ctx.get("db")
    if db is not None:
        yield db
        return

    db_maker = ctx.get("db_maker")
    if db_maker is None:
        from app.db.session import async_session_maker
        db_maker = async_session_maker

    async with db_maker() as session:
        yield session


async def base_startup(ctx: dict[str, Any]) -> None:
    """Initialize resources on worker startup."""
    from app.db.session import async_session_maker

    ctx["db_maker"] = async_session_maker
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

    on_startup = base_startup
    on_shutdown = base_shutdown
