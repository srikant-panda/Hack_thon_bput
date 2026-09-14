"""Phase 5 suite: security history, audit distinction, review chain.

All provider calls are mocked with recording fakes (no real Gmail traffic).
Covers:
1. scan_verdict event (actor system) from the scan route with severity/score/indicators
2. auto quarantine + sender_block events (actor system); manual release (actor user);
   scheduler expiry -> release/sender_expiry (actor scheduler)
3. history API filters + pagination + cross-user isolation
4. /quarantine/{id}/review returns ordered chain + available_actions per status
5. audit_logs.actor_type populated per path (user / system / scheduler)
6. backfill script idempotency (run twice -> no duplicates)
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.core.config import get_settings  # noqa: E402
from app.core.crypto import encrypt_secret  # noqa: E402
from app.core.security import get_current_user  # noqa: E402
from app.db.models import AuditLog, BlockedSender, EmailConnectorAccount, QuarantinedItem, SecurityEvent  # noqa: E402
from app.db.session import async_session_maker, current_user_id  # noqa: E402
from _rls import as_user, create_user_admin  # noqa: E402
from app.main import app  # noqa: E402
from app.schemas.email import NormalizedMessage  # noqa: E402
from app.services.email_providers.gmail import gmail_provider  # noqa: E402
from sqlalchemy import func, select  # noqa: E402


class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def assert_true(self, condition: bool, name: str, details: str = ""):
        if condition:
            self.passed += 1
            print(f"  \033[32m✔ PASS\033[0m: {name}")
        else:
            self.failed += 1
            print(f"  \033[31m✖ FAIL\033[0m: {name} - {details}")

    def report(self):
        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"TEST RESULTS: {self.passed}/{total} passed")
        if self.failed == 0:
            print("\033[32mALL SECURITY HISTORY TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


def _bad_message(message_id: str) -> NormalizedMessage:
    return NormalizedMessage(
        provider_message_id=message_id,
        provider="gmail",
        sender="Evil Sender <phisher@evil-spam.tk>",
        recipients=["victim@example.com"],
        subject="URGENT: verify your account now",
        body_text="Compromised! Visit http://192.168.10.5/verify-login.php and confirm your password.",
    )


def _user(uid: str):
    return SimpleNamespace(id=uid, email=f"{uid}@cyberguard.test", full_name="History Tester", username=None, account_type="user")


class _RecordingAdapter:
    def __init__(self):
        self.calls: list[tuple] = []

    async def ensure_quarantine_label(self, access_token: str) -> str:
        return "Label_Q"

    async def quarantine_message(self, access_token: str, message_id: str, label: str) -> dict:
        self.calls.append(("quarantine_message", message_id))
        return {"id": message_id}

    async def release_message(self, access_token: str, message_id: str, label: str) -> dict:
        self.calls.append(("release_message", message_id))
        return {"id": message_id}

    async def delete_message(self, access_token: str, message_id: str, permanent: bool) -> dict:
        self.calls.append(("delete_message", message_id, permanent))
        return {"id": message_id}

    async def create_sender_rule(self, access_token: str, sender_email: str, target_label: str) -> dict:
        self.calls.append(("create_sender_rule", sender_email))
        return {"id": f"filter-{uuid.uuid4().hex[:6]}"}

    async def delete_sender_rule(self, access_token: str, rule_id: str) -> dict:
        self.calls.append(("delete_sender_rule", rule_id))
        return {"deleted": True}


async def run_security_history_tests(runner: TestRunner) -> None:
    settings = get_settings()
    from cryptography.fernet import Fernet

    _backup_key = settings.CONNECTOR_TOKEN_KEY
    settings.CONNECTOR_TOKEN_KEY = Fernet.generate_key().decode()

    user_a_id = f"hist-a-{uuid.uuid4().hex[:8]}"
    connector_a_id = f"hist-conn-a-{uuid.uuid4().hex[:6]}"
    await create_user_admin(id=user_a_id, email=f"{user_a_id}@gmail.com", is_single_user=True)

    async with as_user(user_a_id), async_session_maker() as db:
        db.add(
            EmailConnectorAccount(
                id=connector_a_id,
                owner_user_id=user_a_id,
                provider="gmail",
                provider_email=f"{user_a_id}@gmail.com",
                status="connected",
                access_token_enc=encrypt_secret("ya29-hist-access"),
                refresh_token_enc=encrypt_secret("1//hist-refresh"),
                access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )
        await db.commit()

    adapter = _RecordingAdapter()
    _method_names = (
        "ensure_quarantine_label", "quarantine_message", "release_message",
        "delete_message", "create_sender_rule", "delete_sender_rule",
    )
    _patches = {name: getattr(gmail_provider, name) for name in _method_names}
    for name in _method_names:
        setattr(gmail_provider, name, getattr(adapter, name))

    def _override(uid):
        async def _fn():
            current_user_id.set(uid)  # RLS identity, as in production
            return _user(uid)

        return _fn

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        from app.services.action_engine import enforce_scan_result
        from app.services.mail_scanner import scan_message
        from app.services.scheduler import run_expiry_once

        # --------------------------------------------------------------
        # 1. Scan -> scan_verdict event (actor system) via the scan route
        # --------------------------------------------------------------
        print("\n[Suite 15.1] scan_verdict events from the scan route")
        message_id = f"hist-msg-{uuid.uuid4().hex[:6]}"
        async def _fake_list(access_token: str, max_results: int = 50) -> list[dict]:
            return [{"id": message_id, "thread_id": "t"}]
        async def _fake_get(access_token: str, mid: str) -> NormalizedMessage:
            return _bad_message(mid)

        _orig_list = gmail_provider.list_messages
        _orig_get = gmail_provider.get_message
        gmail_provider.list_messages = _fake_list
        gmail_provider.get_message = _fake_get

        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            app.dependency_overrides[get_current_user] = _override(user_a_id)
            res = await client.post(f"/api/v1/connectors/{connector_a_id}/scan", json={"scan_recent": 1})
            runner.assert_true(res.status_code == 200, "Scan returns 200", f"status={res.status_code}")

        async with as_user(user_a_id), async_session_maker() as db:
            event = (
                await db.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.owner_user_id == user_a_id,
                        SecurityEvent.event_type == "scan_verdict",
                        SecurityEvent.provider_message_id == message_id,
                    )
                )
            ).scalar_one_or_none()
            runner.assert_true(event is not None, "scan_verdict event recorded")
            if event:
                runner.assert_true(event.actor_type == "system", "scan_verdict actor is system")
                runner.assert_true(event.severity in ("high", "critical"), "scan_verdict carries severity")
                runner.assert_true(event.score is not None and event.score >= 0.4, "scan_verdict carries score")
                runner.assert_true(len(event.indicators or []) > 0, "scan_verdict carries indicators")
                runner.assert_true(bool(event.explanation), "scan_verdict carries explanation")

        # --------------------------------------------------------------
        # 2. Auto quarantine + sender_block (system); manual release (user);
        #    scheduler expiry (scheduler)
        # --------------------------------------------------------------
        print("\n[Suite 15.2] Enforcement + scheduler event chain")
        message = _bad_message(f"hist-enf-{uuid.uuid4().hex[:6]}")
        scan = await scan_message(message)
        async with as_user(user_a_id), async_session_maker() as db:
            connector = (
                await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_a_id))
            ).scalar_one()
            await enforce_scan_result(db, connector, message, scan)

        async with as_user(user_a_id), async_session_maker() as db:
            q_event = (
                await db.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.owner_user_id == user_a_id,
                        SecurityEvent.event_type == "quarantine",
                        SecurityEvent.provider_message_id == message.provider_message_id,
                        SecurityEvent.actor_type == "system",
                    )
                )
            ).scalar_one_or_none()
            runner.assert_true(q_event is not None and q_event.operation_status == "success",
                               "quarantine event recorded with actor=system, status=success")
            b_event = (
                await db.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.owner_user_id == user_a_id,
                        SecurityEvent.event_type == "sender_block",
                        SecurityEvent.sender_email == "phisher@evil-spam.tk",
                    )
                )
            ).scalar_one_or_none()
            runner.assert_true(b_event is not None and "filter" in (b_event.operation_detail or ""),
                               "sender_block event recorded with the Gmail filter id in detail")

        # Manual release via the API (actor user).
        async with as_user(user_a_id), async_session_maker() as db:
            item = (
                await db.execute(
                    select(QuarantinedItem).where(
                        QuarantinedItem.connector_id == connector_a_id,
                        QuarantinedItem.provider_message_id == message.provider_message_id,
                    )
                )
            ).scalar_one()

        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            app.dependency_overrides[get_current_user] = _override(user_a_id)
            res = await client.post(f"/api/v1/enforcement/quarantine/{item.id}/release")
            runner.assert_true(res.status_code == 200, "Manual release returns 200")

        async with as_user(user_a_id), async_session_maker() as db:
            r_event = (
                await db.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.owner_user_id == user_a_id,
                        SecurityEvent.event_type == "release",
                        SecurityEvent.quarantined_item_id == item.id,
                        SecurityEvent.actor_type == "user",
                    )
                )
            ).scalar_one_or_none()
            runner.assert_true(r_event is not None, "release event recorded with actor=user")

        # Scheduler expiry: force the sender block expired and run one pass.
        async with as_user(user_a_id), async_session_maker() as db:
            block = (
                await db.execute(
                    select(BlockedSender).where(
                        BlockedSender.connector_id == connector_a_id,
                        BlockedSender.status == "blocked",
                    )
                )
            ).scalar_one()
            block.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            await db.commit()

        stats = await run_expiry_once()
        runner.assert_true(stats["blocks_expired"] >= 1, "Scheduler expired the block", str(stats))
        async with as_user(user_a_id), async_session_maker() as db:
            se_event = (
                await db.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.owner_user_id == user_a_id,
                        SecurityEvent.event_type == "sender_expiry",
                        SecurityEvent.blocked_sender_id == block.id,
                        SecurityEvent.actor_type == "scheduler",
                    )
                )
            ).scalar_one_or_none()
            runner.assert_true(se_event is not None and "filter" in (se_event.operation_detail or ""),
                               "sender_expiry event recorded with actor=scheduler + rule id")

        # --------------------------------------------------------------
        # 3. History API: filters, pagination, cross-user isolation
        # --------------------------------------------------------------
        print("\n[Suite 15.3] History API filters + isolation")
        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            app.dependency_overrides[get_current_user] = _override(user_a_id)
            res_all = await client.get("/api/v1/security-history?limit=200")
            runner.assert_true(res_all.status_code == 200, "GET /security-history returns 200")
            all_items = res_all.json()["items"]
            runner.assert_true(len(all_items) >= 4, "History lists all events for the owner", f"n={len(all_items)}")

            res_f = await client.get("/api/v1/security-history?event_type=quarantine&actor_type=system")
            f_items = res_f.json()["items"]
            runner.assert_true(
                f_items and all(i["event_type"] == "quarantine" and i["actor_type"] == "system" for i in f_items),
                "event_type + actor_type filters work",
            )
            res_s = await client.get("/api/v1/security-history?sender_email=evil-spam")
            runner.assert_true(
                res_s.json()["items"]
                and all("evil-spam" in (i["sender_email"] or "") for i in res_s.json()["items"]),
                "sender ilike filter works",
            )
            res_p = await client.get("/api/v1/security-history?limit=2&offset=0")
            runner.assert_true(len(res_p.json()["items"]) == 2 and res_p.json()["total"] >= 4,
                               "pagination respects limit and reports total")

            app.dependency_overrides[get_current_user] = _override(f"hist-b-{uuid.uuid4().hex[:6]}")
            res_b = await client.get("/api/v1/security-history")
            runner.assert_true(len(res_b.json()["items"]) == 0, "User B sees 0 history rows")

        # --------------------------------------------------------------
        # 4. Review endpoint: ordered chain + available_actions
        # --------------------------------------------------------------
        print("\n[Suite 15.4] Review record")
        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            app.dependency_overrides[get_current_user] = _override(user_a_id)
            res_review = await client.get(f"/api/v1/quarantine/{item.id}/review")
            runner.assert_true(res_review.status_code == 200, "GET /quarantine/{id}/review returns 200")
            review = res_review.json()
            chain = review["event_chain"]
            runner.assert_true(len(chain) >= 2, f"Chain has >=2 events (got {len(chain)})")
            types_in_order = [e["event_type"] for e in chain]
            stamps = [e["created_at"] for e in chain if e["created_at"]]
            runner.assert_true(stamps == sorted(stamps), "Chain is ordered by created_at ascending")
            # The scan in 15.1 already auto-blocked this sender, so this
            # message's chain legitimately has no second sender_block event
            # (the block is per-sender, not per-message — asserted in 15.2).
            runner.assert_true(
                "quarantine" in types_in_order and "release" in types_in_order,
                f"Chain covers quarantine -> release (got {types_in_order})",
            )
            runner.assert_true(review["item"]["status"] == "released", "Review reflects released status")
            runner.assert_true(review["available_actions"]["release"] is False,
                               "Released item: release no longer available")
            runner.assert_true(review["available_actions"]["delete_mode"] == "trash",
                               "permanent_delete disabled -> delete offered as trash-only")

        # --------------------------------------------------------------
        # 5. audit_logs.actor_type per path
        # --------------------------------------------------------------
        print("\n[Suite 15.5] audit actor_type distinction")
        async with as_user(user_a_id), async_session_maker() as db:
            sys_rows = (await db.execute(
                select(func.count()).select_from(AuditLog).where(
                    AuditLog.owner_user_id == user_a_id, AuditLog.actor_type == "system")
            )).scalar() or 0
            user_rows = (await db.execute(
                select(func.count()).select_from(AuditLog).where(
                    AuditLog.owner_user_id == user_a_id, AuditLog.actor_type == "user")
            )).scalar() or 0
            sched_rows = (await db.execute(
                select(func.count()).select_from(AuditLog).where(
                    AuditLog.owner_user_id == user_a_id, AuditLog.actor_type == "scheduler")
            )).scalar() or 0
        runner.assert_true(sys_rows >= 1, f"system audit rows recorded ({sys_rows})")
        runner.assert_true(user_rows >= 1, f"user audit rows recorded ({user_rows})")
        runner.assert_true(sched_rows >= 1, f"scheduler audit rows recorded ({sched_rows})")

        # --------------------------------------------------------------
        # 6. Backfill idempotency
        # --------------------------------------------------------------
        print("\n[Suite 15.6] Backfill idempotency")
        from scripts.backfill_security_history import backfill

        counts1 = await backfill()
        async with as_user(user_a_id), async_session_maker() as db:
            n1 = (await db.execute(select(func.count()).select_from(SecurityEvent))).scalar()
        counts2 = await backfill()
        async with as_user(user_a_id), async_session_maker() as db:
            n2 = (await db.execute(select(func.count()).select_from(SecurityEvent))).scalar()
        runner.assert_true(n1 == n2, f"Second backfill run adds no duplicates ({n1} -> {n2})", f"{counts1} vs {counts2}")
        runner.assert_true(counts2["quarantine"] == 0 and counts2["sender_block"] == 0,
                           "Second run skips already-recorded source rows")

        app.dependency_overrides.pop(get_current_user, None)

    finally:
        for name, fn in _patches.items():
            setattr(gmail_provider, name, fn)
        gmail_provider.list_messages = _orig_list
        gmail_provider.get_message = _orig_get
        settings.CONNECTOR_TOKEN_KEY = _backup_key


async def _standalone() -> int:
    runner = TestRunner()
    print("\n📜 STARTING CYBERGUARD SECURITY HISTORY TEST SUITE\n" + "=" * 60)
    await run_security_history_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
