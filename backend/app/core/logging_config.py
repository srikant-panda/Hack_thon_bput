"""Structured JSON logging configuration, contextvars propagation, and sensitive data filtering."""

from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Optional

# Contextvars for distributed asynchronous tracing
current_correlation_id: ContextVar[Optional[str]] = ContextVar("current_correlation_id", default=None)
current_job_id: ContextVar[Optional[str]] = ContextVar("current_job_id", default=None)
current_job_type: ContextVar[Optional[str]] = ContextVar("current_job_type", default=None)
current_user_id: ContextVar[Optional[str]] = ContextVar("current_user_id", default=None)
current_worker_name: ContextVar[Optional[str]] = ContextVar("current_worker_name", default=None)

# Regular expressions for redaction of sensitive credentials and message bodies
_SENSITIVE_PATTERNS = [
    # OAuth tokens
    (re.compile(r"ya29\.[a-zA-Z0-9_\-\.]+"), "[REDACTED_TOKEN]"),
    (re.compile(r"1//[a-zA-Z0-9_\-\.]+"), "[REDACTED_TOKEN]"),
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9_\-\.]+"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(access_token[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(refresh_token[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(password[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
    (re.compile(r"(client_secret[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
    # Email content & body payloads
    (re.compile(r"(body(?:_text|_html)?[\"']?\s*[:=]\s*[\"'])(?:\\.|[^\"'\\])*[\"']", re.IGNORECASE), r'\1[REDACTED_BODY]"'),
    (re.compile(r"(attachment_data|content_bytes|raw_content)[\"']?\s*[:=]\s*[\"'](?:\\.|[^\"'\\])*[\"']", re.IGNORECASE), r'\1: "[REDACTED_ATTACHMENT_DATA]"'),
]


def sanitize_sensitive_text(text_val: str) -> str:
    """Scrub sensitive credentials, OAuth tokens, and email body contents from text."""
    if not text_val or not isinstance(text_val, str):
        return str(text_val) if text_val is not None else ""
    cleaned = text_val
    for pattern, replacement in _SENSITIVE_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def set_log_context(
    correlation_id: Optional[str] = None,
    job_id: Optional[str] = None,
    job_type: Optional[str] = None,
    user_id: Optional[str] = None,
    worker_name: Optional[str] = None,
) -> dict[str, Any]:
    """Set ambient logging context for the current async task execution."""
    if correlation_id is not None:
        current_correlation_id.set(str(correlation_id))
    if job_id is not None:
        current_job_id.set(str(job_id))
    if job_type is not None:
        current_job_type.set(str(job_type))
    if user_id is not None:
        current_user_id.set(str(user_id))
    if worker_name is not None:
        current_worker_name.set(str(worker_name))

    return {
        "correlation_id": current_correlation_id.get(),
        "job_id": current_job_id.get(),
        "job_type": current_job_type.get(),
        "user_id": current_user_id.get(),
        "worker_name": current_worker_name.get(),
    }


def clear_log_context() -> None:
    """Clear all ambient logging context variables to prevent leakage across jobs."""
    current_correlation_id.set(None)
    current_job_id.set(None)
    current_job_type.set(None)
    current_user_id.set(None)
    current_worker_name.set(None)


def get_log_context() -> dict[str, Optional[str]]:
    """Retrieve current ambient context values."""
    return {
        "correlation_id": current_correlation_id.get(),
        "job_id": current_job_id.get(),
        "job_type": current_job_type.get(),
        "user_id": current_user_id.get(),
        "worker_name": current_worker_name.get(),
    }


class SensitiveDataFilter(logging.Filter):
    """Logging filter to intercept and redact secrets, tokens, and email bodies."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: sanitize_sensitive_text(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(sanitize_sensitive_text(str(a)) for a in record.args)
        return True


class StructuredJsonFormatter(logging.Formatter):
    """Structured JSON log formatter with contextvar resolution and token redaction."""

    def format(self, record: logging.LogRecord) -> str:
        # Resolve fields from record attribute first, falling back to contextvars
        corr_id = getattr(record, "correlation_id", None) or current_correlation_id.get()
        j_id = getattr(record, "job_id", None) or current_job_id.get()
        j_type = getattr(record, "job_type", None) or current_job_type.get()
        u_id = getattr(record, "user_id", None) or current_user_id.get()
        w_name = getattr(record, "worker_name", None) or current_worker_name.get()

        raw_message = record.getMessage()
        sanitized_message = sanitize_sensitive_text(raw_message)

        # Standard ISO-like timestamp
        record_time = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        record_ms = int(record.msecs)
        timestamp_str = f"{record_time},{record_ms:03d}"

        log_obj: dict[str, Any] = {
            "timestamp": timestamp_str,
            "level": record.levelname,
            "logger": record.name,
            "message": sanitized_message,
            "correlation_id": corr_id,
            "job_id": j_id,
            "job_type": j_type,
            "user_id": u_id,
            "worker_name": w_name,
        }

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def configure_structured_logging(level: int = logging.INFO) -> None:
    """Configure structured JSON logging on the root logger and cyberguard namespaces."""
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    handler.addFilter(SensitiveDataFilter())

    root = logging.getLogger()
    root.setLevel(level)

    # Replace existing handlers with structured handler
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)

    # Ensure cyberguard namespace propagates
    cg_logger = logging.getLogger("cyberguard")
    cg_logger.setLevel(level)
    for h in list(cg_logger.handlers):
        cg_logger.removeHandler(h)
    cg_logger.addHandler(handler)
    cg_logger.propagate = False
