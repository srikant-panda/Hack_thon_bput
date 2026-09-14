"""Phase 4 suite: enforcement, quarantine, sender rules, expiry scheduler.

All Gmail adapter methods are mocked with recording fakes — no real provider
calls. Covers:
- connector settings update/retrieve via API
- auto-quarantine: critical scan -> adapter.quarantine_message called,
  QuarantinedItem row with correct expires_at
- sender rule: create_sender_rule called, BlockedSender row created
- manual release via API -> adapter.release_message called, status updated
- expiry scheduler: expired QuarantinedItem -> release_message called,
  status becomes expired; expired BlockedSender -> rule deleted
- honest failure: adapter raising insufficient_scope -> operation logged as
  failed and the failure surfaces in the ScanResult / API envelope
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
from app.db.models import BlockedSender, ConnectorOperationLog, EmailConnectorAccount, QuarantinedItem  # noqa: E402
from app.db.session import async_session_maker, current_user_id  # noqa: E402
from _rls import as_user, create_user_admin  # noqa: E402
from app.main import app  # noqa: E402
from sqlalchemy import select  # noqa: E402
from app.schemas.email import NormalizedMessage  # noqa: E402
from app.services.email_providers.base import EmailProviderError, ProviderErrorClass  # noqa: E402
from app.services.email_providers.gmail import gmail_provider  # noqa: E402


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
            print("\033[32mALL ENFORCEMENT TESTS PASSED SUCCESSFULLY!\033[0m")
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
    return SimpleNamespace(id=uid, email=f"{uid}@cyberguard.test", full_name="Enforcement Tester", username=None, account_type="user")


class _RecordingAdapter:
    """Records every enforcement call made on the Gmail provider."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.quarantine_error: Exception | None = None

    async def ensure_quarantine_label(self, access_token: str) -> str:
        self.calls.append(("ensure_quarantine_label", access_token))
        return "Label_Q"

    async def quarantine_message(self, access_token: str, message_id: str, label: str) -> dict:
        self.calls.append(("quarantine_message", message_id, label))
        if self.quarantine_error:
            raise self.quarantine_error
        return {"id": message_id}

    async def release_message(self, access_token: str, message_id: str, label: str) -> dict:
        self.calls.append(("release_message", message_id, label))
        return {"id": message_id}

    async def delete_message(self, access_token: str, message_id: str, permanent: bool) -> dict:
        self.calls.append(("delete_message", message_id, permanent))
        return {"id": message_id}

    async def create_sender_rule(self, access_token: str, sender_email: str, target_label: str) -> dict:
        self.calls.append(("create_sender_rule", sender_email, target_label))
        return {"id": f"filter-{uuid.uuid4().hex[:6]}"}

    async def delete_sender_rule(self, access_token: str, rule_id: str) -> dict:
        self.calls.append(("delete_sender_rule", rule_id))
        return {"deleted": True}


async def run_enforcement_tests(runner: TestRunner) -> None:
    settings = get_settings()
    from cryptography.fernet import Fernet

    _backup_key = settings.CONNECTOR_TOKEN_KEY
    settings.CONNECTOR_TOKEN_KEY = Fernet.generate_key().decode()

    user_a_id = f"enf-a-{uuid.uuid4().hex[:8]}"
    connector_a_id = f"enf-conn-a-{uuid.uuid4().hex[:6]}"
    await create_user_admin(id=user_a_id, email=f"{user_a_id}@gmail.com", is_single_user=True)

    # Connector with a valid (future-expiry) access token.
    async with as_user(user_a_id), async_session_maker() as db:
        db.add(
            EmailConnectorAccount(
                id=connector_a_id,
                owner_user_id=user_a_id,
                provider="gmail",
                provider_email=f"{user_a_id}@gmail.com",
                status="connected",
                access_token_enc=encrypt_secret("ya29-enf-test-access"),
                refresh_token_enc=encrypt_secret("1//enf-test-refresh"),
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

    try:
        # --------------------------------------------------------------
        # 13.1 Settings: update & retrieve
        # --------------------------------------------------------------
        print("\n[Suite 13.1] Connector settings")
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            app.dependency_overrides[get_current_user] = _override(user_a_id)

            res = await client.put(
                f"/api/v1/connectors/{connector_a_id}/settings",
                json={"expiry_mode": "hours", "quarantine_expiry_hours": 3,
                      "permanent_delete_enabled": True, "auto_quarantine_enabled": True},
            )
            runner.assert_true(res.status_code == 200, "PUT settings returns 200", f"status={res.status_code}")
            data = res.json()
            runner.assert_true(data["quarantine_expiry_hours"] == 3, "Expiry updated to 3 hours")
            runner.assert_true(data["permanent_delete_enabled"] is True, "Permanent delete toggled on")

            res = await client.get(f"/api/v1/connectors/{connector_a_id}/settings")
            runner.assert_true(res.status_code == 200 and res.json()["quarantine_expiry_hours"] == 3,
                               "GET settings reflects the update")

            res = await client.put(
                f"/api/v1/connectors/{connector_a_id}/settings", json={"expiry_mode": "manual"}
            )
            runner.assert_true(res.status_code == 200 and res.json()["quarantine_expiry_hours"] is None,
                               "Manual (never expire) sets NULL expiry")

            # Restore 3h + auto for later cases
            await client.put(
                f"/api/v1/connectors/{connector_a_id}/settings",
                json={"expiry_mode": "hours", "quarantine_expiry_hours": 3},
            )

        # --------------------------------------------------------------
        # 13.2 + 13.3 Action engine: auto-quarantine + sender rule
        # --------------------------------------------------------------
        print("\n[Suite 13.2/13.3] Auto-quarantine & sender rule")
        from app.services.action_engine import enforce_scan_result
        from app.services.mail_scanner import scan_message

        message = _bad_message(f"msg-enf-{uuid.uuid4().hex[:6]}")
        scan = await scan_message(message)
        runner.assert_true(scan.overall_severity in ("high", "critical"),
                           f"Fixture scans HIGH/CRITICAL (got {scan.overall_severity})")

        async with as_user(user_a_id), async_session_maker() as db:
            connector = (
                await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_a_id))
            ).scalar_one()
            result = await enforce_scan_result(db, connector, message, scan)

        runner.assert_true(result.provider_operation_status == "success",
                           f"Enforcement succeeds (got {result.provider_operation_status}: {result.provider_operation_detail})")
        runner.assert_true(
            ("quarantine_message", message.provider_message_id, "Label_Q") in adapter.calls,
            "Adapter quarantine_message called with the right message/label",
        )
        runner.assert_true(
            any(c[0] == "create_sender_rule" and c[1] == "phisher@evil-spam.tk" for c in adapter.calls),
            "Adapter create_sender_rule called for the sender",
        )

        async with as_user(user_a_id), async_session_maker() as db:
            items = (
                await db.execute(select(QuarantinedItem).where(QuarantinedItem.connector_id == connector_a_id))
            ).scalars().all()
            runner.assert_true(len(items) == 1, "QuarantinedItem row created")
            item = items[0] if items else None
            if item:
                runner.assert_true(item.provider_message_id == message.provider_message_id, "Item references the message")
                runner.assert_true(item.expires_at is not None, "Item has an expiry (3h setting)")
                delta = item.expires_at - item.quarantined_at
                runner.assert_true(
                    2.9 <= delta.total_seconds() / 3600 <= 3.1,
                    f"Expiry matches the 3h setting (got {delta})",
                )
                runner.assert_true(bool(item.scan_result_json), "Item stores the full Phase 3 ScanResult JSON")
            blocks = (
                await db.execute(select(BlockedSender).where(BlockedSender.connector_id == connector_a_id))
            ).scalars().all()
            runner.assert_true(len(blocks) == 1, "BlockedSender row created")
            block = blocks[0] if blocks else None
            if block:
                runner.assert_true(block.provider_rule_id, "Block stores the Gmail filter id")
                runner.assert_true(block.expires_at is not None, "Block expiry matches settings")

        # Idempotency: second enforcement of same sender does not duplicate blocks.
        message2 = _bad_message(f"msg-enf2-{uuid.uuid4().hex[:6]}")
        scan2 = await scan_message(message2)
        async with as_user(user_a_id), async_session_maker() as db:
            connector = (
                await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_a_id))
            ).scalar_one()
            result = await enforce_scan_result(db, connector, message2, scan2)
        runner.assert_true(
            result.provider_operation_status == "success" and "already blocked" in (result.provider_operation_detail or ""),
            "Repeat offense reuses the existing block (no duplicate filter)",
        )

        # --------------------------------------------------------------
        # 13.5 Expiry scheduler
        # --------------------------------------------------------------
        print("\n[Suite 13.5] Expiry scheduler")
        from app.services.scheduler import run_expiry_once

        # Force the item + block to be expired now.
        async with as_user(user_a_id), async_session_maker() as db:
            for row in (await db.execute(select(QuarantinedItem))).scalars().all():
                row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
            for row in (await db.execute(select(BlockedSender))).scalars().all():
                row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
            await db.commit()

        stats = await run_expiry_once()
        runner.assert_true(stats["quarantine_expired"] >= 1, "Scheduler released expired quarantine", str(stats))
        runner.assert_true(stats["blocks_expired"] >= 1, "Scheduler expired the sender block", str(stats))
        runner.assert_true(
            any(c[0] == "release_message" for c in adapter.calls), "Adapter release_message called by scheduler"
        )
        runner.assert_true(
            any(c[0] == "delete_sender_rule" for c in adapter.calls), "Adapter delete_sender_rule called by scheduler"
        )
        async with as_user(user_a_id), async_session_maker() as db:
            item_rows = (
                await db.execute(
                    select(QuarantinedItem).where(QuarantinedItem.connector_id == connector_a_id)
                )
            ).scalars().all()
            block_rows = (
                await db.execute(select(BlockedSender).where(BlockedSender.connector_id == connector_a_id))
            ).scalars().all()
        runner.assert_true(
            item_rows and all(i.status == "expired" for i in item_rows),
            f"QuarantinedItem status is expired ({[i.status for i in item_rows]})",
        )
        runner.assert_true(
            block_rows and all(b.status == "expired" for b in block_rows),
            f"BlockedSender status is expired ({[b.status for b in block_rows]})",
        )

        # --------------------------------------------------------------
        # 13.6 Honest failure: insufficient_scope from provider
        # --------------------------------------------------------------
        print("\n[Suite 13.6] Honest failure reporting")
        adapter.quarantine_error = EmailProviderError(
            ProviderErrorClass.INSUFFICIENT_SCOPE, "Gmail access denied.", provider_code="403"
        )
        message3 = _bad_message(f"msg-enf3-{uuid.uuid4().hex[:6]}")
        scan3 = await scan_message(message3)
        async with as_user(user_a_id), async_session_maker() as db:
            connector = (
                await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_a_id))
            ).scalar_one()
            result = await enforce_scan_result(db, connector, message3, scan3)
        adapter.quarantine_error = None

        runner.assert_true(result.provider_operation_status == "failed",
                           "Failed enforcement reports provider_operation_status=failed")
        runner.assert_true("insufficient_scope" in (result.provider_operation_detail or ""),
                           "Failure detail names the error class")
        async with as_user(user_a_id), async_session_maker() as db:
            fail_logs = (
                await db.execute(
                    select(ConnectorOperationLog).where(
                        ConnectorOperationLog.owner_user_id == user_a_id,
                        ConnectorOperationLog.status == "failed",
                    )
                )
            ).scalars().all()
            runner.assert_true(len(fail_logs) >= 1, "Failure recorded in operation log with status=failed")

        # API surface: enforcement endpoints behave on released/expired data.
        print("\n[Suite 13.4] Manual release API")
        # Re-arm an active item by force-quarantining a message with a working adapter.
        message4 = _bad_message(f"msg-enf4-{uuid.uuid4().hex[:6]}")
        scan4 = await scan_message(message4)
        async with as_user(user_a_id), async_session_maker() as db:
            connector = (
                await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_a_id))
            ).scalar_one()
            await enforce_scan_result(db, connector, message4, scan4)

        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            app.dependency_overrides[get_current_user] = _override(user_a_id)

            res_list = await client.get("/api/v1/enforcement/quarantine")
            runner.assert_true(res_list.status_code == 200, "GET /enforcement/quarantine returns 200")
            active = [i for i in res_list.json()["items"] if i["status"] == "quarantined"]
            runner.assert_true(len(active) >= 1, "Quarantine queue lists the active item")

            res = await client.post(f"/api/v1/enforcement/quarantine/{active[-1]['id']}/release")
            runner.assert_true(res.status_code == 200, "POST release returns 200", f"status={res.status_code}")
            runner.assert_true(res.json()["status"] == "released", "Release updates status to released")
            runner.assert_true(
                any(c[0] == "release_message" for c in adapter.calls),
                "Manual release called adapter release_message",
            )

            # User B must not see or touch user A's items.
            app.dependency_overrides[get_current_user] = _override(f"enf-b-{uuid.uuid4().hex[:8]}")
            res_b = await client.get("/api/v1/enforcement/quarantine")
            runner.assert_true(len(res_b.json()["items"]) == 0, "User B sees an empty quarantine queue")
            res_b_post = await client.post(f"/api/v1/enforcement/quarantine/{active[-1]['id']}/release")
            runner.assert_true(res_b_post.status_code == 404, "User B cannot release user A's item (404)")

            app.dependency_overrides[get_current_user] = _override(user_a_id)
            # Re-arm the block (the scheduler test expired it) to exercise the API path.
            async with as_user(user_a_id), async_session_maker() as db:
                re_block = (
                    await db.execute(select(BlockedSender).where(BlockedSender.id == block.id))
                ).scalar_one()
                re_block.status = "blocked"
                re_block.expires_at = datetime.now(timezone.utc) + timedelta(hours=2)
                await db.commit()
            res_bs = await client.get("/api/v1/enforcement/blocked-senders")
            runner.assert_true(res_bs.status_code == 200, "GET /enforcement/blocked-senders returns 200")
            res_unblock = await client.post(f"/api/v1/enforcement/blocked-senders/{block.id}/release")
            runner.assert_true(res_unblock.status_code == 200 and res_unblock.json()["status"] == "released",
                               "Unblock sender works and updates status")

        app.dependency_overrides.pop(get_current_user, None)

    finally:
        for name, fn in _patches.items():
            setattr(gmail_provider, name, fn)
        settings.CONNECTOR_TOKEN_KEY = _backup_key


async def _standalone() -> int:
    runner = TestRunner()
    print("\n🛡️ STARTING CYBERGUARD ENFORCEMENT TEST SUITE\n" + "=" * 60)
    await run_enforcement_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
