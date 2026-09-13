"""Backfill security_events from existing enforcement data (Phase 5).

Idempotent: a source row is skipped when a security_event already exists for
it (quarantined_items → event_type='quarantine' via quarantined_item_id;
blocked_senders → event_type='sender_block' via blocked_sender_id;
connector_operation_logs → matching connector events via
connector_id+operation+created_at mapping where a 1:1 mapping exists).

Usage (run ONCE against the configured database):
    cd backend && uv run python scripts/backfill_security_history.py
"""

import asyncio
import os
import sys
import uuid
from datetime import timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


async def _already_recorded(db, *, quarantined_item_id=None, blocked_sender_id=None) -> bool:
    from sqlalchemy import select

    from app.db.models import SecurityEvent

    if quarantined_item_id is not None:
        row = (
            await db.execute(
                select(SecurityEvent.id).where(
                    SecurityEvent.quarantined_item_id == quarantined_item_id
                )
            )
        ).first()
        if row:
            return True
    if blocked_sender_id is not None:
        row = (
            await db.execute(
                select(SecurityEvent.id).where(
                    SecurityEvent.blocked_sender_id == blocked_sender_id
                )
            )
        ).first()
        if row:
            return True
    return False


async def backfill() -> dict:
    from sqlalchemy import select

    from app.db.admin import _get_admin_session_maker
    from app.db.models import BlockedSender, ConnectorOperationLog, QuarantinedItem, SecurityEvent

    session_maker = _get_admin_session_maker()
    counts = {"quarantine": 0, "sender_block": 0, "connector_events": 0, "skipped": 0}

    async with session_maker() as db:
        # --- quarantined items -> quarantine events ---
        items = (await db.execute(select(QuarantinedItem))).scalars().all()
        for item in items:
            if await _already_recorded(db, quarantined_item_id=item.id):
                counts["skipped"] += 1
                continue
            scan = item.scan_result_json or {}
            db.add(
                SecurityEvent(
                    id=str(uuid.uuid4()),
                    owner_user_id=item.owner_user_id,
                    event_type="quarantine",
                    actor_type="system",
                    connector_id=item.connector_id,
                    provider="gmail",
                    provider_message_id=item.provider_message_id,
                    sender_email=item.sender_email,
                    subject=scan.get("subject"),
                    severity=item.severity,
                    score=scan.get("overall_score"),
                    explanation=scan.get("overall_explanation"),
                    action_requested=item.reason,
                    action_performed="quarantine",
                    operation_status="success",
                    operation_detail="Backfilled from quarantined_items (pre-history enforcement record)",
                    quarantined_item_id=item.id,
                    created_at=item.quarantined_at,
                )
            )
            await db.commit()
            counts["quarantine"] += 1

        # --- blocked senders -> sender_block events ---
        blocks = (await db.execute(select(BlockedSender))).scalars().all()
        for block in blocks:
            if await _already_recorded(db, blocked_sender_id=block.id):
                counts["skipped"] += 1
                continue
            db.add(
                SecurityEvent(
                    id=str(uuid.uuid4()),
                    owner_user_id=block.owner_user_id,
                    event_type="sender_block",
                    actor_type="system",
                    connector_id=block.connector_id,
                    provider="gmail",
                    sender_email=block.sender_email,
                    action_requested=block.reason,
                    action_performed="create_sender_rule",
                    operation_status="success" if block.provider_rule_id else "failed",
                    operation_detail=(
                        f"Gmail filter {block.provider_rule_id} (backfilled from blocked_senders)"
                        if block.provider_rule_id
                        else "Backfilled from blocked_senders; no filter id recorded"
                    ),
                    blocked_sender_id=block.id,
                    created_at=block.blocked_at,
                )
            )
            await db.commit()
            counts["sender_block"] += 1

        # --- connector operation logs -> connector lifecycle events ---
        # 1:1 mapping only for terminal lifecycle operations (connect/test/
        # disconnect); flow operations (token_refresh, callback) stay out.
        op_to_event = {
            "callback": "connector_connect",
            "test_connection": "connector_test",
            "disconnect": "connector_disconnect",
        }
        logs = (
            await db.execute(select(ConnectorOperationLog).order_by(ConnectorOperationLog.created_at.asc()))
        ).scalars().all()
        seen = set()
        for log in logs:
            event_type = op_to_event.get(log.operation)
            if event_type is None or log.status != "success":
                continue
            key = (log.connector_id or log.owner_user_id, event_type)
            if key in seen:
                # keep one lifecycle event per connector+type from logs
                continue
            seen.add(key)
            existing = (
                await db.execute(
                    select(SecurityEvent.id).where(
                        SecurityEvent.owner_user_id == log.owner_user_id,
                        SecurityEvent.event_type == event_type,
                        SecurityEvent.connector_id == log.connector_id,
                    )
                )
            ).first()
            if existing:
                counts["skipped"] += 1
                continue
            db.add(
                SecurityEvent(
                    id=str(uuid.uuid4()),
                    owner_user_id=log.owner_user_id,
                    event_type=event_type,
                    actor_type="user",
                    connector_id=log.connector_id,
                    provider=log.provider,
                    operation_status="success",
                    operation_detail=f"Backfilled from connector_operation_logs: {log.message or log.operation}",
                    created_at=log.created_at,
                )
            )
            await db.commit()
            counts["connector_events"] += 1

    return counts


async def main() -> int:
    counts = await backfill()
    print(
        "Backfill complete: "
        f"quarantine={counts['quarantine']}, sender_block={counts['sender_block']}, "
        f"connector_events={counts['connector_events']}, skipped(already recorded)={counts['skipped']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
