"""Expiry scheduler (Phase 4): auto-release expired quarantines and blocks.

Runs as a simple asyncio background loop (every 5 minutes, started from the
app lifespan) — no extra dependency. Every pass:

1. QuarantinedItem rows with ``status='quarantined'`` and ``expires_at < now``
   are released at Gmail (quarantine label removed, INBOX restored) and their
   status becomes ``expired``.
2. BlockedSender rows with ``status='blocked'`` and ``expires_at < now`` have
   their Gmail filter deleted and their status becomes ``expired``.

The loop accesses rows across users, so it runs on the service-role admin
engine (RLS bypass); connector tokens are decrypted in runtime only. Provider
failures are recorded on the row (``last_error``) and retried on the next pass
— the item stays quarantined/blocked, which is the safe side.
"""

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.db.admin import _get_admin_session_maker
from email.utils import parseaddr

from sqlalchemy import select

from app.db.models import (
    BlockedSender,
    ConnectorOperationLog,
    EmailConnectorAccount,
    QuarantinedItem,
    SecurityEvent,
)
from app.services.email_providers import get_provider
from app.services.email_providers.base import EmailProviderError
from app.services.action_engine import enforce_scan_results
from app.services.connectors.token_manager import TokenRefreshError, get_valid_access_token
from app.services.mail_scanner import scan_message
from app.services.security_history_service import record_event
from app.services.trusted_senders import annotate_scan_with_trust, is_sender_trusted

logger = logging.getLogger("cyberguard.scheduler")

INTERVAL_SECONDS = 300

_running_task: asyncio.Task | None = None


async def _connector_token(db, connector_id: str, owner_user_id: str) -> tuple[str, object]:
    from app.db.models import EmailConnectorAccount

    result = await db.execute(
        select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_id)
    )
    connector = result.scalar_one_or_none()
    if connector is None or connector.status == "revoked":
        raise RuntimeError(f"connector {connector_id} unavailable")
    token = await get_valid_access_token(connector, db)
    return token, connector


async def run_expiry_once() -> dict:
    """One scheduler pass. Returns counters for logging/tests."""
    from app.db.admin import _get_admin_session_maker

    session_maker = _get_admin_session_maker()
    now = datetime.now(timezone.utc)
    stats = {"quarantine_expired": 0, "blocks_expired": 0, "failures": 0}

    async with session_maker() as db:
        # --- expired quarantines ---
        items = (
            await db.execute(
                select(QuarantinedItem).where(
                    QuarantinedItem.status == "quarantined",
                    QuarantinedItem.expires_at.is_not(None),
                    QuarantinedItem.expires_at < now,
                )
            )
        ).scalars().all()
        for item in items:
            try:
                token, connector = await _connector_token(db, item.connector_id, item.owner_user_id)
                provider = get_provider(connector.provider)
                label_id = await provider.ensure_quarantine_label(token)
                await provider.release_message(token, item.provider_message_id, label_id)
                item.status = "expired"
                item.last_error = None
                db.add(
                    ConnectorOperationLog(
                        owner_user_id=item.owner_user_id,
                        connector_id=item.connector_id,
                        provider="gmail",
                        operation="expiry_release",
                        status="success",
                        message=f"Quarantine expired; released {item.provider_message_id} to inbox",
                    )
                )
                await record_event(
                    db,
                    owner_user_id=item.owner_user_id,
                    event_type="release",
                    actor_type="scheduler",
                    connector_id=item.connector_id,
                    provider="gmail",
                    provider_message_id=item.provider_message_id,
                    sender_email=item.sender_email,
                    subject=(item.scan_result_json or {}).get("subject"),
                    severity=item.severity,
                    score=(item.scan_result_json or {}).get("overall_score"),
                    action_requested="quarantine",
                    action_performed="auto_release_expiry",
                    operation_status="success",
                    operation_detail="Quarantine expired per user settings; message returned to the inbox",
                    quarantined_item_id=item.id,
                )
                await db.commit()
                stats["quarantine_expired"] += 1
            except (EmailProviderError, TokenRefreshError, RuntimeError) as exc:
                item.last_error = f"{type(exc).__name__}: {getattr(exc, 'message', exc)}"
                await db.commit()
                stats["failures"] += 1
                logger.warning("Quarantine expiry release failed for %s: %s", item.id, item.last_error)

        # --- expired sender blocks ---
        blocks = (
            await db.execute(
                select(BlockedSender).where(
                    BlockedSender.status == "blocked",
                    BlockedSender.expires_at.is_not(None),
                    BlockedSender.expires_at < now,
                )
            )
        ).scalars().all()
        for block in blocks:
            try:
                token, connector = await _connector_token(db, block.connector_id, block.owner_user_id)
                provider = get_provider(connector.provider)
                if block.provider_rule_id:
                    await provider.delete_sender_rule(token, block.provider_rule_id)
                block.status = "expired"
                block.last_error = None
                db.add(
                    ConnectorOperationLog(
                        owner_user_id=block.owner_user_id,
                        connector_id=block.connector_id,
                        provider="gmail",
                        operation="expiry_unblock",
                        status="success",
                        message=f"Sender block expired; filter removed for {block.sender_email}",
                    )
                )
                await record_event(
                    db,
                    owner_user_id=block.owner_user_id,
                    event_type="sender_expiry",
                    actor_type="scheduler",
                    connector_id=block.connector_id,
                    provider="gmail",
                    sender_email=block.sender_email,
                    action_requested="block_sender",
                    action_performed="delete_sender_rule",
                    operation_status="success",
                    operation_detail=f"Block expired per user settings; Gmail filter {block.provider_rule_id} removed",
                    blocked_sender_id=block.id,
                )
                await db.commit()
                stats["blocks_expired"] += 1
            except (EmailProviderError, TokenRefreshError, RuntimeError) as exc:
                block.last_error = f"{type(exc).__name__}: {getattr(exc, 'message', exc)}"
                # An undecryptable stored token (CONNECTOR_TOKEN_KEY rotated) is
                # permanently unrecoverable: mark the connector reauth_required
                # so the UI shows "reconnect needed" and this pass stops
                # retrying the same dead row every cycle.
                if isinstance(exc, RuntimeError) and "cannot be decrypted" in str(exc):
                    connector_row = await db.get(EmailConnectorAccount, block.connector_id)
                    if connector_row is not None:
                        connector_row.status = "reauth_required"
                        connector_row.last_error = block.last_error
                await db.commit()
                stats["failures"] += 1
                logger.warning("Block expiry failed for %s: %s", block.id, block.last_error)

    if any(stats.values()):
        logger.info("Expiry scheduler pass: %s", stats)
    return stats


AUTO_SCAN_INTERVAL_SECONDS = 120


async def run_auto_scan_once() -> dict:
    """Auto-scan pass (FP/demo hardening): the backend now notices NEW mail
    without a manual scan click. Every connected personal mailbox is polled;
    messages already analyzed (a scan_verdict security event exists for the
    provider_message_id) are skipped, so each new email is scanned exactly
    once, shortly after arrival. Enforcement reuses the production action
    engine (corroboration gate + trust list included)."""
    stats = {"connectors_scanned": 0, "messages_scanned": 0, "failures": 0}
    session_maker = _get_admin_session_maker()
    async with session_maker() as db:
        conn_ids = (
            await db.execute(
                select(EmailConnectorAccount.id).where(
                    EmailConnectorAccount.status == "connected"
                )
            )
        ).scalars().all()

    for conn_id in conn_ids:
        # One session per connector: a rollback after a mailbox failure must
        # not expire the ORM objects used by later iterations (AsyncSession
        # forbids implicit lazy loads — the classic MissingGreenlet trap).
        async with session_maker() as db:
            try:
                connector = await db.get(EmailConnectorAccount, conn_id)
                if connector is None or connector.status != "connected":
                    continue
                token = await get_valid_access_token(connector, db)
                provider = get_provider(connector.provider)
                caps = provider.capabilities or {}
                if isinstance(caps, dict) and not caps.get("supports_read", True):
                    continue
                entries = await provider.list_messages(token, max_results=10)
                message_ids = [e["id"] for e in entries]
                if not message_ids:
                    continue
                already = set(
                    (
                        await db.execute(
                            select(SecurityEvent.provider_message_id).where(
                                SecurityEvent.owner_user_id == connector.owner_user_id,
                                SecurityEvent.event_type == "scan_verdict",
                                SecurityEvent.provider_message_id.in_(message_ids),
                            )
                        )
                    ).scalars().all()
                )
                fresh_ids = [mid for mid in message_ids if mid not in already]
                if not fresh_ids:
                    continue
                pairs = []
                for mid in fresh_ids:
                    message = await provider.get_message(token, mid)
                    scan = await scan_message(message)
                    if await is_sender_trusted(db, connector.owner_user_id, _sender_of(message)):
                        scan = annotate_scan_with_trust(scan)
                    pairs.append((message, scan))
                    await record_event(
                        db,
                        owner_user_id=connector.owner_user_id,
                        event_type="scan_verdict",
                        actor_type="system",
                        connector=connector,
                        provider_message_id=message.provider_message_id,
                        sender_email=message.sender,
                        subject=message.subject,
                        severity=scan.overall_severity,
                        score=scan.overall_score,
                        explanation=scan.overall_explanation,
                        action_requested=scan.recommended_action,
                        operation_status="success",
                        operation_detail="auto-scan (scheduler)",
                    )
                results = await enforce_scan_results(db, connector, pairs)
                stats["connectors_scanned"] += 1
                stats["messages_scanned"] += len(results)
                await db.commit()
                logger.info(
                    "Auto-scan %s: %d new message(s) analyzed for %s",
                    connector.provider, len(results), connector.provider_email,
                )
            except Exception as exc:  # noqa: BLE001 - one mailbox must not stall the rest
                stats["failures"] += 1
                logger.warning("Auto-scan failed for connector %s: %s", conn_id, exc)
                await db.rollback()
    if stats["connectors_scanned"] or stats["failures"]:
        logger.info("Auto-scan pass: %s", stats)
    return stats


def _sender_of(message) -> str:
    _, addr = parseaddr(message.sender or "")
    return (addr or message.sender or "").strip().lower()


async def _auto_scan_loop() -> None:
    while True:
        try:
            await run_auto_scan_once()
        except Exception:  # noqa: BLE001 - the scheduler must never crash the loop
            logger.exception("Auto-scan pass failed")
        await asyncio.sleep(AUTO_SCAN_INTERVAL_SECONDS)


_auto_scan_task: asyncio.Task | None = None


def start_scheduler() -> None:
    global _running_task, _auto_scan_task
    if _running_task is None or _running_task.done():
        _running_task = asyncio.create_task(_loop())
        logger.info("Expiry scheduler started (interval %ss)", INTERVAL_SECONDS)
    if _auto_scan_task is None or _auto_scan_task.done():
        _auto_scan_task = asyncio.create_task(_auto_scan_loop())
        logger.info("Auto-scan scheduler started (interval %ss)", AUTO_SCAN_INTERVAL_SECONDS)


def stop_scheduler() -> None:
    global _running_task, _auto_scan_task
    for name, task_var in (("Expiry scheduler", "_running_task"), ("Auto-scan scheduler", "_auto_scan_task")):
        task = globals().get(task_var)
        if task is not None:
            task.cancel()
            globals()[task_var] = None
            logger.info(f"{name} stopped")
