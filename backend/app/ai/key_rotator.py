"""Distributed OpenRouter API key rotation with fault-tolerant circuit breaking and background re-release."""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.key_rotator")

OPENROUTER_AUTH_URL = "https://openrouter.ai/api/v1/auth/key"


def mask_key(key: str) -> str:
    """Mask an API key for safe logging (e.g. sk-or-v1-6638...4df8)."""
    if not key:
        return "none"
    if len(key) <= 12:
        return f"{key[:3]}...{key[-3:]}"
    return f"{key[:10]}...{key[-4:]}"


@dataclass
class KeyState:
    key: str
    masked: str
    is_healthy: bool = True
    failure_count: int = 0
    last_failure_time: float = 0.0
    down_reason: str = ""
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    last_probed_time: float = 0.0


class ApiKeyRotator:
    """Distributed Round-Robin API Key Rotator with Circuit Breaking and Free-Time Recovery."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyState] = {}
        self._key_list: list[str] = []
        self._lock = asyncio.Lock()
        self._rr_index = 0
        self._cooldown_seconds = 60
        self._health_check_interval = 30
        self._background_task: Optional[asyncio.Task] = None
        self._running = False
        self._initialized = False

    def initialize(self, keys: list[str], cooldown_seconds: int = 60, health_check_interval: int = 30) -> None:
        """Initialize or re-configure rotator with a list of keys."""
        self._cooldown_seconds = max(1, cooldown_seconds)
        self._health_check_interval = max(1, health_check_interval)

        new_dict: dict[str, KeyState] = {}
        new_list: list[str] = []

        for k in keys:
            clean = k.strip()
            if clean and clean not in new_dict:
                # Retain existing telemetry if key was already tracked
                existing = self._keys.get(clean)
                if existing:
                    new_dict[clean] = existing
                else:
                    new_dict[clean] = KeyState(key=clean, masked=mask_key(clean))
                new_list.append(clean)

        self._keys = new_dict
        self._key_list = new_list
        self._initialized = True
        logger.info(
            "ApiKeyRotator initialized with %d key(s) (Cooldown: %ds, Health check interval: %ds)",
            len(self._key_list),
            self._cooldown_seconds,
            self._health_check_interval,
        )

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            settings = get_settings()
            self.initialize(
                keys=settings.openrouter_keys_list,
                cooldown_seconds=settings.OPENROUTER_KEY_COOLDOWN_SECONDS,
                health_check_interval=settings.OPENROUTER_HEALTH_CHECK_INTERVAL_SECONDS,
            )

    async def get_next_key(self) -> tuple[Optional[str], str]:
        """Select next available API key using distributed round-robin across healthy keys."""
        self._ensure_initialized()

        if not self._key_list:
            return None, "none"

        now = time.time()
        async with self._lock:
            # 1. Check if any cooled-down keys can be automatically recovered
            for state in self._keys.values():
                if not state.is_healthy and (now - state.last_failure_time >= self._cooldown_seconds):
                    state.is_healthy = True
                    state.down_reason = "cooldown expired"
                    logger.info("Key %s cooldown expired; re-released to active pool", state.masked)

            # 2. Get all currently healthy keys
            healthy = [self._keys[k] for k in self._key_list if self._keys[k].is_healthy]

            if healthy:
                # Distributed load balancing: round-robin selection
                selected = healthy[self._rr_index % len(healthy)]
                self._rr_index = (self._rr_index + 1) % len(healthy)
                selected.total_requests += 1
                return selected.key, selected.masked

            # 3. All keys are marked down: fallback to the least-recently failed key
            logger.warning("All %d OpenRouter API keys are currently marked down! Selecting oldest key for retry.", len(self._key_list))
            oldest = min(self._keys.values(), key=lambda s: s.last_failure_time)
            oldest.total_requests += 1
            return oldest.key, oldest.masked

    def mark_key_down(self, key: str, reason: str, status_code: Optional[int] = None) -> None:
        """Mark an API key down in the circuit breaker cache and start cooldown."""
        state = self._keys.get(key)
        if not state:
            return

        state.is_healthy = False
        state.last_failure_time = time.time()
        state.failure_count += 1
        state.total_failures += 1
        state.down_reason = f"{reason} (HTTP {status_code})" if status_code else reason

        healthy_count = sum(1 for s in self._keys.values() if s.is_healthy)
        logger.warning(
            "Marked API key %s DOWN: %s. Active pool: %d/%d healthy",
            state.masked,
            state.down_reason,
            healthy_count,
            len(self._keys),
        )

    def mark_key_success(self, key: str) -> None:
        """Record successful request completion and reinforce healthy status."""
        state = self._keys.get(key)
        if state:
            state.is_healthy = True
            state.total_successes += 1
            state.failure_count = 0
            state.down_reason = ""

    async def probe_key(self, state: KeyState) -> bool:
        """Lightweight health probe to OpenRouter auth endpoint to test key recovery."""
        state.last_probed_time = time.time()
        headers = {
            "Authorization": f"Bearer {state.key}",
            "HTTP-Referer": "https://cyberguard.local",
            "X-Title": "CYBERGUARD Health Check",
        }
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                res = await client.get(OPENROUTER_AUTH_URL, headers=headers)
                if res.status_code == 200:
                    state.is_healthy = True
                    state.failure_count = 0
                    state.down_reason = ""
                    logger.info("Health probe succeeded for key %s. Re-released into rotation pool.", state.masked)
                    return True
                if res.status_code in (429, 401, 402):
                    state.last_failure_time = time.time()
                    state.down_reason = f"Probe returned HTTP {res.status_code}"
                    logger.debug("Health probe for key %s returned HTTP %s (remains down).", state.masked, res.status_code)
                    return False
        except Exception as exc:
            state.last_failure_time = time.time()
            logger.debug("Health probe exception for key %s: %s", state.masked, exc)
            return False
        return False

    async def _background_loop(self) -> None:
        """Periodic background task that checks and re-releases recovered keys."""
        logger.info("OpenRouter key health monitor background loop started")
        while self._running:
            try:
                await asyncio.sleep(self._health_check_interval)
                now = time.time()

                downed_keys = [
                    s for s in self._keys.values()
                    if not s.is_healthy and (now - s.last_failure_time >= self._cooldown_seconds)
                ]

                for state in downed_keys:
                    await self.probe_key(state)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in key rotator background loop: %s", exc)

    def start_background_task(self) -> None:
        """Start the background recovery loop."""
        self._ensure_initialized()
        if not self._running:
            self._running = True
            self._background_task = asyncio.create_task(self._background_loop())

    def stop_background_task(self) -> None:
        """Stop the background recovery loop."""
        self._running = False
        if self._background_task and not self._background_task.done():
            self._background_task.cancel()

    def get_status(self) -> list[dict[str, Any]]:
        """Return runtime status and metrics for all registered keys."""
        self._ensure_initialized()
        now = time.time()
        result = []
        for state in self._keys.values():
            if not state.is_healthy and (now - state.last_failure_time >= self._cooldown_seconds):
                state.is_healthy = True
                state.down_reason = "cooldown expired"
            cooldown_remaining = max(0, int(self._cooldown_seconds - (now - state.last_failure_time))) if not state.is_healthy else 0
            result.append({
                "masked_key": state.masked,
                "is_healthy": state.is_healthy,
                "failure_count": state.failure_count,
                "down_reason": state.down_reason,
                "cooldown_remaining_seconds": cooldown_remaining,
                "total_requests": state.total_requests,
                "total_successes": state.total_successes,
                "total_failures": state.total_failures,
            })
        return result


# Singleton instance
_rotator_instance = ApiKeyRotator()


def get_key_rotator() -> ApiKeyRotator:
    """Return the global ApiKeyRotator instance."""
    return _rotator_instance
