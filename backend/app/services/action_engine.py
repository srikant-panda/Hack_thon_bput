"""Action engine (Phase 4): provider-backed enforcement on scan results.

Closes the analysis loop: when the scanner recommends quarantine and the user
has auto-enforcement enabled, this service performs the real Gmail operations
(label-based quarantine, filter-based sender blocking) and records every
outcome — success or honest failure — in the database.
"""

import logging
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    BlockedSender,
    ConnectorOperationLog,
    ConnectorSettings,
    EmailConnectorAccount,
    QuarantinedItem,
)
from app.schemas.email import NormalizedMessage
from app.schemas.scan_results import ScanResult
from app.services.security_history_service import record_event
from app.services.connectors.token_manager import TokenRefreshError, get_valid_access_token
from app.services.email_providers.base import EmailProviderError
from app.services.email_providers.gmail import gmail_provider

logger = logging.getLogger("cyberguard.action_engine")


class EnforcementOutcome(Exception):
    """Raised internally to short-circuit with an honest failure result."""


def _sender_email(from_header: str) -> str:
    _, addr = parseaddr(from_header or "")
    return (addr or from_header or "").strip().lower()


async def get_or_create_settings(db: AsyncSession, connector: EmailConnectorAccount) -> ConnectorSettings:
    result = await db.execute(
        select(ConnectorSettings).where(ConnectorSettings.connector_id == connector.id)
    )
    settings = result.scalar_one_or_none()
    if settings is None:
        settings = ConnectorSettings(
            owner_user_id=connector.owner_user_id,
            connector_id=connector.id,
            quarantine_expiry_hours=24,
            permanent_delete_enabled=False,
            auto_quarantine_enabled=True,
        )
        db.add(settings)
        await db.commit()
        await db.refresh(settings)
    return settings


async def _log(db: AsyncSession, connector: EmailConnectorAccount, operation: str, status: str, message: str, connector_id: str | None = None) -> None:
    db.add(
        ConnectorOperationLog(
            owner_user_id=connector.owner_user_id,
            connector_id=connector_id or connector.id,
            provider=connector.provider,
            operation=operation,
            status=status,
            message=message,
        )
    )
    await db.commit()


async def _get_token(db: AsyncSession, connector: EmailConnectorAccount) -> str:
    try:
        return await get_valid_access_token(connector, db)
    except TokenRefreshError as exc:
        raise EnforcementOutcome(exc.error_class, exc.message) from exc
    except RuntimeError as exc:  # e.g. CONNECTOR_TOKEN_KEY missing
        raise EnforcementOutcome("configuration_error", str(exc)) from exc


async def enforce_scan_result(
    db: AsyncSession, connector: EmailConnectorAccount, message: NormalizedMessage, scan: ScanResult
) -> ScanResult:
    """Execute provider-backed enforcement for one scan result.

    Mutates (and returns) the ScanResult so the API response reflects the real
    provider operation outcome instead of the Phase 3 deferral.
    """
    settings = await get_or_create_settings(db, connector)

    if scan.recommended_action == "none":
        scan.provider_operation_status = "no_action_required"
        scan.provider_operation_detail = "No enforcement action was recommended for this verdict."
        return scan

    if not settings.auto_quarantine_enabled:
        scan.provider_operation_status = "skipped_auto_enforcement_disabled"
        scan.provider_operation_detail = (
            "Auto-enforcement is disabled for this connector in Settings; the "
            "recommendation is advisory only. Nothing was changed in the mailbox."
        )
        await _log(db, connector, "enforcement", "success",
                   f"Auto-enforcement disabled; advisory only for {scan.message_id}")
        return scan

    sender = _sender_email(message.sender)
    try:
        token = await _get_token(db, connector)
        label_id = await gmail_provider.ensure_quarantine_label(token)

        # 1. Quarantine the message itself.
        await gmail_provider.quarantine_message(token, message.provider_message_id, label_id)

        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=settings.quarantine_expiry_hours)
            if settings.quarantine_expiry_hours
            else None
        )
        item = QuarantinedItem(
            owner_user_id=connector.owner_user_id,
            connector_id=connector.id,
            provider_message_id=message.provider_message_id,
            sender_email=sender,
            reason=f"{scan.overall_severity} verdict: {scan.recommended_action}",
            severity=scan.overall_severity,
            scan_result_json=scan.model_dump(mode="json"),
            expires_at=expires_at,
            status="quarantined",
        )
        db.add(item)
        await db.commit()
        await db.refresh(item)

        # 2. Block the sender via a Gmail filter (once per sender).
        rule_id: str | None = None
        rule_note = ""
        if scan.overall_severity in ("critical", "high"):
            existing = await db.execute(
                select(BlockedSender).where(
                    BlockedSender.connector_id == connector.id,
                    BlockedSender.sender_email == sender,
                    BlockedSender.status == "blocked",
                )
            )
            if existing.scalar_one_or_none() is None:
                rule = await gmail_provider.create_sender_rule(token, sender, label_id)
                rule_id = str(rule.get("id", ""))
                block_row = BlockedSender(
                    owner_user_id=connector.owner_user_id,
                    connector_id=connector.id,
                    sender_email=sender,
                    provider_rule_id=rule_id,
                    reason=f"Auto-blocked: {scan.overall_severity} message",
                    expires_at=expires_at,
                    status="blocked",
                )
                db.add(block_row)
                await db.commit()
                await db.refresh(block_row)
                block_id = block_row.id
            else:
                rule_note = " Sender already blocked."

        scan.provider_operation_status = "success"
        scan.provider_operation_detail = (
            f"Message quarantined at Gmail (label '{gmail_provider.QUARANTINE_LABEL_NAME}', "
            f"removed from INBOX)"
            + (f"; sender {sender} auto-blocked via filter" if rule_id else "")
            + (rule_note)
            + (
                f"; auto-release in {settings.quarantine_expiry_hours}h"
                if expires_at
                else "; manual expiry (no auto-release)"
            )
            + "."
        )
        # Keep the stored review snapshot consistent with the final outcome.
        item.scan_result_json = scan.model_dump(mode="json")
        await db.commit()

        # Security history (Phase 5): the real provider operations just performed.
        await record_event(
            db,
            owner_user_id=connector.owner_user_id,
            event_type="quarantine",
            actor_type="system",
            connector=connector,
            provider_message_id=message.provider_message_id,
            sender_email=sender,
            subject=message.subject,
            severity=scan.overall_severity,
            score=scan.overall_score,
            explanation=scan.overall_explanation,
            action_requested=scan.recommended_action,
            action_performed="quarantine",
            operation_status="success",
            operation_detail=f"Gmail label '{gmail_provider.QUARANTINE_LABEL_NAME}' applied, INBOX removed",
            quarantined_item_id=item.id,
        )
        if rule_id:
            await record_event(
                db,
                owner_user_id=connector.owner_user_id,
                event_type="sender_block",
                actor_type="system",
                connector=connector,
                provider_message_id=message.provider_message_id,
                sender_email=sender,
                subject=message.subject,
                severity=scan.overall_severity,
                action_requested="block_sender",
                action_performed="create_sender_rule",
                operation_status="success",
                operation_detail=f"Gmail filter {rule_id} auto-quarantines future mail from {sender}",
                blocked_sender_id=block_id,
            )
        await _log(db, connector, "enforcement", "success",
                   f"Quarantined {message.provider_message_id} from {sender}", connector_id=connector.id)
        return scan

    except (EmailProviderError, EnforcementOutcome) as exc:
        error_class = getattr(exc, "error_class", "api_error")
        message_text = getattr(exc, "message", str(exc))
        await record_event(
            db,
            owner_user_id=connector.owner_user_id,
            event_type="quarantine",
            actor_type="system",
            connector=connector,
            provider_message_id=message.provider_message_id,
            sender_email=sender,
            subject=message.subject,
            severity=scan.overall_severity,
            score=scan.overall_score,
            action_requested=scan.recommended_action,
            action_performed="quarantine",
            operation_status=error_class if error_class in ("failed", "insufficient_scope", "reauth_required") else "failed",
            operation_detail=message_text,
        )
        scan.provider_operation_status = "failed"
        scan.provider_operation_detail = (
            f"Provider operation failed ({error_class}): {message_text} "
            "Nothing was changed unless a prior step had already succeeded."
        )
        await _log(db, connector, "enforcement", "failed", message_text)
        logger.warning("Enforcement failed for %s (%s): %s", message.provider_message_id, error_class, message_text)
        return scan
    except Exception as exc:  # noqa: BLE001 - never mask a real failure as success
        scan.provider_operation_status = "failed"
        scan.provider_operation_detail = f"Enforcement failed unexpectedly: {type(exc).__name__}: {exc}"
        await _log(db, connector, "enforcement", "failed", str(exc))
        logger.exception("Unexpected enforcement failure")
        return scan


async def enforce_scan_results(
    db: AsyncSession,
    connector: EmailConnectorAccount,
    pairs: list[tuple[NormalizedMessage, ScanResult]],
) -> list[ScanResult]:
    """Enforce a batch of scan results, skipping when auto-enforcement is off."""
    if not pairs:
        return [scan for _, scan in pairs]
    settings = await get_or_create_settings(db, connector)
    if not settings.auto_quarantine_enabled:
        outs = []
        for _, scan in pairs:
            if scan.recommended_action != "none":
                scan.provider_operation_status = "skipped_auto_enforcement_disabled"
                scan.provider_operation_detail = (
                    "Auto-enforcement is disabled for this connector in Settings; "
                    "the recommendation is advisory only."
                )
            else:
                scan.provider_operation_status = "no_action_required"
            outs.append(scan)
        return outs
    return [await enforce_scan_result(db, connector, message, scan) for message, scan in pairs]
