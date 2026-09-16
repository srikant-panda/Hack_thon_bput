"""Retry and backoff policies for asynchronous pipeline jobs and poison message handling (RT-10)."""

from __future__ import annotations

import logging
import random
from typing import Any, Optional

from app.core.config import get_settings
from app.services.gmail.client import (
    GmailAuthError,
    GmailRateLimitError,
    GmailServerError,
)

logger = logging.getLogger("cyberguard.retry_policy")


class MIMECorruptionError(Exception):
    """Poison message error caused by unparseable or corrupted MIME payload structure."""
    pass


class OversizedEmail(Exception):
    """Poison message error caused by payload exceeding byte, part, or body boundaries."""
    pass


class NetworkTimeout(Exception):
    """Transient timeout error communicating with upstream network service."""
    pass


# Standard exponential backoff schedule: 5s, 30s, 2min (120s), 10min (600s), 30min (1800s)
STANDARD_BACKOFF_DELAYS = [5, 30, 120, 600, 1800]

# Rate limit backoff schedule: 30s, 5min (300s), 30min (1800s), 2h (7200s), 6h (21600s)
RATE_LIMIT_BACKOFF_DELAYS = [30, 300, 1800, 7200, 21600]

# Classification categories
CATEGORY_AUTH = "auth"
CATEGORY_RATE_LIMIT = "rate_limit"
CATEGORY_POISON = "poison"
CATEGORY_TRANSIENT = "transient"


class RetryDecision:
    """Encapsulates retry decision, target status, and delay calculation."""

    def __init__(
        self,
        should_retry: bool,
        next_status: str,
        delay_seconds: int,
        error_category: str,
        reason: str,
    ):
        self.should_retry = should_retry
        self.next_status = next_status
        self.delay_seconds = delay_seconds
        self.error_category = error_category
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"RetryDecision(should_retry={self.should_retry}, next_status='{self.next_status}', "
            f"delay_seconds={self.delay_seconds}, category='{self.error_category}', reason='{self.reason}')"
        )

    @property
    def status(self) -> str:
        return self.next_status

    @property
    def is_poison(self) -> bool:
        return self.error_category in (CATEGORY_POISON, CATEGORY_AUTH)

    def to_dict(self) -> dict[str, Any]:
        return {
            "should_retry": self.should_retry,
            "next_status": self.next_status,
            "delay_seconds": self.delay_seconds,
            "error_category": self.error_category,
            "reason": self.reason,
        }


def classify_error(exc_or_str: Any) -> str:
    """Classify an exception or error message into one of four retry behavior categories."""
    if exc_or_str is None:
        return CATEGORY_TRANSIENT

    # Exception type classification
    if isinstance(exc_or_str, GmailAuthError):
        return CATEGORY_AUTH
    if isinstance(exc_or_str, GmailRateLimitError):
        return CATEGORY_RATE_LIMIT
    if isinstance(exc_or_str, (MIMECorruptionError, OversizedEmail)):
        return CATEGORY_POISON
    if isinstance(exc_or_str, (NetworkTimeout, GmailServerError, TimeoutError)):
        return CATEGORY_TRANSIENT

    # String message classification fallback
    err_str = str(exc_or_str).lower()
    if any(k in err_str for k in ("auth", "401", "reauth_required", "invalid_grant", "unauthorized")):
        return CATEGORY_AUTH
    if any(k in err_str for k in ("mimecorruption", "oversizedemail", "poison_pill")):
        return CATEGORY_POISON
    if any(k in err_str for k in ("rate_limit", "429", "quota", "user_rate_limit_exceeded")):
        return CATEGORY_RATE_LIMIT
    return CATEGORY_TRANSIENT


def compute_retry_delay(
    retry_count: int,
    error_category: Any = CATEGORY_TRANSIENT,
    jitter: Optional[bool] = None,
) -> int:
    """Calculate the backoff delay in seconds based on retry count, error type, and optional jitter."""
    settings = get_settings()
    apply_jitter = jitter if jitter is not None else getattr(settings, "RETRY_JITTER_ENABLED", True)

    category = error_category if isinstance(error_category, str) else classify_error(error_category)
    delays = RATE_LIMIT_BACKOFF_DELAYS if category == CATEGORY_RATE_LIMIT else STANDARD_BACKOFF_DELAYS

    if retry_count <= 0:
        base_delay = delays[0]
    else:
        idx = min(retry_count - 1, len(delays) - 1)
        base_delay = delays[idx]

    # Jitter only applies to rate limits to prevent thundering herd
    if category == CATEGORY_RATE_LIMIT and apply_jitter:
        # +/- 10% jitter to prevent thundering herd across worker pool
        jitter_factor = random.uniform(0.9, 1.1)
        return max(1, int(round(base_delay * jitter_factor)))
    return base_delay


def evaluate_retry_policy(
    error: Any,
    retry_count: int = 0,
    max_retries: Optional[int] = None,
    jitter: Optional[bool] = None,
    current_retry: Optional[int] = None,
) -> RetryDecision:
    """Evaluate whether an error warrants retry, the next state machine status, and delay."""
    if current_retry is not None:
        retry_count = current_retry
    settings = get_settings()
    m_retries = max_retries if max_retries is not None else getattr(settings, "RETRY_MAX_RETRIES", 5)

    category = classify_error(error)

    # 1. Non-retryable errors (Auth revocation or Poison pill) -> Immediate dead_letter
    if category == CATEGORY_AUTH:
        return RetryDecision(
            should_retry=False,
            next_status="dead_letter",
            delay_seconds=0,
            error_category=category,
            reason="GmailAuthError (401): user re-authentication required",
        )

    if category == CATEGORY_POISON:
        return RetryDecision(
            should_retry=False,
            next_status="dead_letter",
            delay_seconds=0,
            error_category=category,
            reason="Poison pill payload (corrupted MIME or oversized email): unrecoverable",
        )

    # 2. Maximum retries exceeded -> dead_letter
    if retry_count >= m_retries:
        return RetryDecision(
            should_retry=False,
            next_status="dead_letter",
            delay_seconds=0,
            error_category=category,
            reason=f"Exceeded maximum retries ({m_retries}): transitioned to dead_letter",
        )

    # 3. Retryable transient error -> calculate delay with category-specific curve
    delay = compute_retry_delay(retry_count, error_category=category, jitter=jitter)
    return RetryDecision(
        should_retry=True,
        next_status="failed",  # remains failed until re-enqueued/picked up
        delay_seconds=delay,
        error_category=category,
        reason=f"Retryable error ({category}): retry {retry_count} of {m_retries} scheduled in {delay}s",
    )
