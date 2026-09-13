"""Trusted-sender feedback loop (FP-hardening, Deliverable 1).

When a user releases a quarantined message and chooses "Release & trust
sender", the sender is recorded here. Future messages from that sender_email
still get the full scan (verdicts are never hidden), but auto-enforcement
becomes recommend-only with an explicit "sender is in your trust list"
annotation — the user's release decision teaches the system instead of the
quarantine → release → re-quarantine loop repeating forever.
"""

import logging
from email.utils import parseaddr

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.url_reputation import get_registrable_domain
from app.db.models import TrustedSender
from app.schemas.scan_results import FeatureAnalysis, ScanResult

logger = logging.getLogger("cyberguard.trusted_senders")

TRUST_ANNOTATION = "You previously released a message from this sender."


def _normalize_email(sender: str) -> str:
    """'Medium <noreply@medium.com>' -> 'noreply@medium.com' (lowercased)."""
    _, addr = parseaddr(sender or "")
    return (addr or sender or "").strip().lower()


def sender_domain_of(sender_email: str) -> str | None:
    domain = sender_email.rsplit("@", 1)[-1].lower() if "@" in sender_email else ""
    if not domain or "." not in domain:
        return None
    return get_registrable_domain(domain)


async def is_sender_trusted(db: AsyncSession, owner_user_id: str, sender: str) -> bool:
    """True when the message sender (normalized email address) is trusted."""
    email = _normalize_email(sender)
    if not email:
        return False
    row = await db.execute(
        select(TrustedSender.id).where(
            TrustedSender.owner_user_id == owner_user_id,
            TrustedSender.sender_email == email,
        )
    )
    return row.scalar_one_or_none() is not None


async def trust_sender(
    db: AsyncSession, owner_user_id: str, sender: str, reason: str
) -> tuple[TrustedSender, bool]:
    """Idempotently trust a sender. Returns (row, created)."""
    email = _normalize_email(sender)
    existing = await db.execute(
        select(TrustedSender).where(
            TrustedSender.owner_user_id == owner_user_id,
            TrustedSender.sender_email == email,
        )
    )
    row = existing.scalar_one_or_none()
    if row is not None:
        if reason and reason != row.reason:
            row.reason = reason
            await db.commit()
            await db.refresh(row)
        return row, False
    entry = TrustedSender(
        owner_user_id=owner_user_id,
        sender_email=email,
        sender_domain=sender_domain_of(email),
        reason=reason,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry, True


async def untrust_sender(db: AsyncSession, owner_user_id: str, sender: str) -> bool:
    email = _normalize_email(sender)
    result = await db.execute(
        delete(TrustedSender).where(
            TrustedSender.owner_user_id == owner_user_id,
            TrustedSender.sender_email == email,
        )
    )
    await db.commit()
    return (result.rowcount or 0) > 0


async def list_trusted(db: AsyncSession, owner_user_id: str) -> list[TrustedSender]:
    rows = await db.execute(
        select(TrustedSender)
        .where(TrustedSender.owner_user_id == owner_user_id)
        .order_by(TrustedSender.created_at.desc())
    )
    return list(rows.scalars().all())


def annotate_scan_with_trust(scan: ScanResult) -> ScanResult:
    """Append the trust-list note to the scan explanation (D1 annotation).

    Scan still runs and verdicts are still shown — the annotation only makes
    the recommend-only enforcement decision explainable in the UI/event chain.
    """
    scan.overall_explanation = (
        f"{scan.overall_explanation}\n"
        f"Trust list: {TRUST_ANNOTATION} Auto-enforcement is recommend-only "
        "for this sender; nothing will be changed in the mailbox automatically."
    )
    # Indicator-level note surfaced in the verbose panel as its own engine row.
    scan.feature_analyses.append(
        FeatureAnalysis(
            engine="trust_list",
            severity="safe",
            score=0.0,
            explanation=(
                f"{TRUST_ANNOTATION} The verdict above is advisory: enforcement "
                "is recommend-only for trusted senders."
            ),
            indicators=[],
        )
    )
    return scan
