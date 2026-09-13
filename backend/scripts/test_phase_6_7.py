"""Phase 6 & 7 suite: provider-neutral contract + event email notifications.

Covers:
1. Contract test: MockEmailProvider implements all 14 methods with expected
   mock payloads; Gmail adapter satisfies the same interface.
2. Capability test: the action engine consults provider.capabilities — a
   provider without sender-rule support skips filter creation honestly.
3. Notification trigger: a quarantine event renders + logs an email to the
   user's notification_email (never the connected mailbox address).
4. Cross-user isolation: user B sees 0 notification-log rows (RLS pattern).
"""

import asyncio
import inspect
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
from app.db.models import BlockedSender, EmailConnectorAccount, NotificationLog, QuarantinedItem, User  # noqa: E402
from app.db.session import async_session_maker  # noqa: E402
from app.main import app  # noqa: E402
from app.schemas.email import NormalizedMessage  # noqa: E402
from app.services.email_providers import get_provider  # noqa: E402
from app.services.email_providers.base import EmailProvider  # noqa: E402
from app.services.email_providers.gmail import gmail_provider  # noqa: E402
from app.services.email_providers.mock_provider import MockEmailProvider  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

CONTRACT_METHODS = [
    "authorize", "refresh_token", "list_messages", "get_message", "get_attachment",
    "create_draft", "send_message", "modify_message", "move_to_trash",
    "delete_message", "quarantine_message", "create_sender_rule",
    "update_sender_rule", "delete_sender_rule",
]


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
            print("\033[32mALL PHASE 6-7 TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


def _bad_message(message_id: str) -> NormalizedMessage:
    return NormalizedMessage(
        provider_message_id=message_id,
        provider="mock",
        sender="Evil Sender <phisher@evil-spam.tk>",
        recipients=["victim@example.com"],
        subject="URGENT: verify your account now",
        body_text="Compromised! Visit http://192.168.10.5/verify-login.php and confirm your password.",
    )


def _user(uid: str, notification_email: str | None = None):
    return SimpleNamespace(
        id=uid, email=f"{uid}@cyberguard.test", full_name="P67 Tester",
        username=None, account_type="user", notification_email=notification_email,
    )


async def run_phase_6_7_tests(runner: TestRunner) -> None:
    settings = get_settings()
    from cryptography.fernet import Fernet

    _backup_key = settings.CONNECTOR_TOKEN_KEY
    settings.CONNECTOR_TOKEN_KEY = Fernet.generate_key().decode()

    # --------------------------------------------------------------
    # 16.1 Contract test: all 14 methods, both providers
    # --------------------------------------------------------------
    print("\n[Suite 16.1] Provider-neutral contract (14 methods)")
    mock = MockEmailProvider()
    missing = [m for m in CONTRACT_METHODS if not hasattr(mock, m) or not callable(getattr(mock, m))]
    runner.assert_true(not missing, f"MockEmailProvider implements all 14 methods (missing: {missing})")

    gmail_missing = [m for m in CONTRACT_METHODS if not callable(getattr(gmail_provider, m, None))]
    runner.assert_true(not gmail_missing, f"Gmail adapter implements all 14 methods (missing: {gmail_missing})")

    # Signatures are coroutine functions (async contract)
    non_async = [m for m in CONTRACT_METHODS if not inspect.iscoroutinefunction(getattr(mock, m))]
    runner.assert_true(not non_async, f"All contract methods are async (non-async: {non_async})")

    # Mock behavior: end-to-end against in-memory state
    mock.seed_message("m-1", sender="phisher@evil-spam.tk")
    caps = mock.capabilities
    runner.assert_true(
        caps.get("supports_permanent_delete") is True and caps.get("supports_sender_rules") is True,
        "Mock capabilities expose supports_* flags",
    )
    label = await mock.ensure_quarantine_label("tok")
    q = await mock.quarantine_message("tok", "m-1", label)
    runner.assert_true(
        label in q.get("labelIds", []) and "INBOX" not in q.get("labelIds", []),
        "Mock quarantine adds the label and removes INBOX",
    )
    rel = await mock.release_message("tok", "m-1", label)
    runner.assert_true("INBOX" in rel["labelIds"], "Mock release restores INBOX")
    rule = await mock.create_sender_rule("tok", "phisher@evil-spam.tk", label)
    upd = await mock.update_sender_rule("tok", rule["id"], "other@evil-spam.tk", label)
    runner.assert_true(upd["updated"] is True and mock.state["filters"][upd["rule_id"]]["from"] == "other@evil-spam.tk",
                       "Mock update_sender_rule updates the filter")
    await mock.delete_sender_rule("tok", upd["rule_id"])
    runner.assert_true(upd["rule_id"] not in mock.state["filters"], "Mock delete_sender_rule removes the filter")
    draft = await mock.create_draft("tok", "raw-mime")
    sent = await mock.send_message("tok", "raw-mime")
    runner.assert_true(draft["id"] in mock.state["drafts"] and sent["id"] in mock.state["messages"],
                       "Mock create_draft/send_message store state")
    tr = await mock.move_to_trash("tok", "m-1")
    runner.assert_true(tr.get("trashed") is True, "Mock move_to_trash trashes the message")
    auth = await mock.authorize(redirect_uri="http://cb", state="s1")
    runner.assert_true("authorization_url" in auth, "Mock authorize returns an authorization_url")

    runner.assert_true(
        get_provider("gmail") is gmail_provider and get_provider("mock") is not None,
        "get_provider resolves registered providers",
    )
    try:
        get_provider("outlook")
        runner.assert_true(False, "get_provider raises unsupported for unknown providers")
    except Exception as exc:
        runner.assert_true("not supported" in str(exc), "get_provider raises unsupported for unknown providers")

    # --------------------------------------------------------------
    # 16.2 Capability-gated enforcement with the mock provider
    # --------------------------------------------------------------
    print("\n[Suite 16.2] Capability-gated enforcement")
    from app.services.action_engine import enforce_scan_result
    from app.services.mail_scanner import scan_message

    user_a_id = f"p67-a-{uuid.uuid4().hex[:8]}"
    user_b_id = f"p67-b-{uuid.uuid4().hex[:8]}"
    conn_a_id = f"p67-conn-a-{uuid.uuid4().hex[:6]}"
    conn_norules_id = f"p67-conn-nr-{uuid.uuid4().hex[:6]}"

    async with async_session_maker() as db:
        db.add(User(id=user_a_id, email=f"{user_a_id}@t.local", is_single_user=True,
                    notification_email="owner-alerts@registered.test"))
        db.add(User(id=user_b_id, email=f"{user_b_id}@t.local", is_single_user=True))
        db.add(EmailConnectorAccount(
            id=conn_a_id, owner_user_id=user_a_id, provider="mock",
            provider_email=f"{user_a_id}@mock.test", status="connected",
            access_token_enc=encrypt_secret("mock-access"),
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ))
        db.add(EmailConnectorAccount(
            id=conn_norules_id, owner_user_id=user_a_id, provider="mock",
            provider_email=f"{user_a_id}-nr@mock.test", status="connected",
            access_token_enc=encrypt_secret("mock-access"),
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ))
        await db.commit()

    engine_mock = MockEmailProvider()
    engine_mock.seed_message("m-enf-1", sender="phisher@evil-spam.tk")
    import app.services.action_engine as action_engine

    _orig_get_provider = action_engine.get_provider

    def _factory_for(mock_instance):
        def _get(name):
            if name == "mock":
                return mock_instance
            return _orig_get_provider(name)
        return _get

    # The engine resolves providers through this factory — patch it there.
    action_engine.get_provider = _factory_for(engine_mock)

    message = _bad_message("m-enf-1")
    scan = await scan_message(message)
    async with async_session_maker() as db:
        connector = (
            await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == conn_a_id))
        ).scalar_one()
        result = await enforce_scan_result(db, connector, message, scan)

    runner.assert_true(result.provider_operation_status == "success",
                       "Mock-provider enforcement succeeds end-to-end")
    runner.assert_true(
        any(c[0] == "quarantine_message" and c[1] == "m-enf-1" for c in engine_mock.calls),
        "Engine drove the mock provider through the contract (quarantine)",
    )
    runner.assert_true(
        any(c[0] == "create_sender_rule" for c in engine_mock.calls),
        "Engine created a sender rule via the mock provider",
    )

    # Provider without sender-rule support: rule skipped honestly.
    norules_mock = MockEmailProvider(supports_sender_rules=False)
    norules_mock.seed_message("m-enf-2", sender="second@evil-spam.tk")
    action_engine.get_provider = _factory_for(norules_mock)
    message2 = _bad_message("m-enf-2")
    scan2 = await scan_message(message2)
    async with async_session_maker() as db:
        connector_nr = (
            await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == conn_norules_id))
        ).scalar_one()
        result2 = await enforce_scan_result(db, connector_nr, message2, scan2)

    runner.assert_true(result2.provider_operation_status == "success",
                       "Non-rules provider still quarantines (capability respected)")
    runner.assert_true(
        not any(c[0] == "create_sender_rule" for c in norules_mock.calls),
        "Engine skips sender rules when capabilities say unsupported",
    )
    async with async_session_maker() as db:
        nr_blocks = (
            await db.execute(select(func.count()).select_from(BlockedSender).where(
                BlockedSender.connector_id == conn_norules_id))
        ).scalar()
    runner.assert_true(nr_blocks == 0, "No BlockedSender row for a rules-incapable provider")

    # --------------------------------------------------------------
    # 16.3 Notification trigger (recipient = notification_email, never the
    # connected mailbox) + 16.4 isolation
    # --------------------------------------------------------------
    print("\n[Suite 16.3] Notification trigger + recipient boundary")
    # The engine's quarantine event (above) should have notified the owner.
    async with async_session_maker() as db:
        logs = (
            await db.execute(select(NotificationLog).where(NotificationLog.owner_user_id == user_a_id))
        ).scalars().all()
        runner.assert_true(len(logs) >= 1, "Notification log row created by the quarantine event")
        if logs:
            log = logs[0]
            runner.assert_true(log.recipient_email == "owner-alerts@registered.test",
                               "Recipient is the registered notification_email")
            runner.assert_true(log.recipient_email != f"{user_a_id}@mock.test",
                               "Recipient is NOT the connected mailbox address")
            runner.assert_true(log.subject.startswith("CYBERGUARD Alert:"),
                               f"Subject uses the standard template ({log.subject!r})")
            runner.assert_true("CYBERGUARD Alert" in (log.body_html or ""), "Body uses the standard template")
            runner.assert_true(log.status == "sent" and log.backend == "db_log",
                               "DB-logged backend recorded the delivery as sent")

    # --------------------------------------------------------------
    # 16.4 Cross-user isolation via API (RLS pattern)
    # --------------------------------------------------------------
    print("\n[Suite 16.4] Notification log isolation")
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    def _override(uid, notif=None):
        async def _fn():
            return _user(uid, notif)

        return _fn

    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
        app.dependency_overrides[get_current_user] = _override(user_a_id, "owner-alerts@registered.test")
        res_a = await client.get("/api/v1/notifications")
        runner.assert_true(res_a.status_code == 200 and len(res_a.json()["items"]) >= 1,
                           "Owner lists their notification logs")

        app.dependency_overrides[get_current_user] = _override(user_b_id)
        res_b = await client.get("/api/v1/notifications")
        runner.assert_true(res_b.status_code == 200 and len(res_b.json()["items"]) == 0,
                           "User B sees 0 notification rows (isolation)")

        # notification_email registration round-trip
        app.dependency_overrides[get_current_user] = _override(user_b_id, None)
        registered = f"alerts-{uuid.uuid4().hex[:6]}@safe.test"
        res_put = await client.put("/api/v1/auth/notification-email",
                                   json={"notification_email": registered})
        runner.assert_true(res_put.status_code == 200 and res_put.json()["notification_email"] == registered,
                           "PUT /auth/notification-email registers the address")
        # get_current_user re-reads the row each request; mimic that in the override.
        app.dependency_overrides[get_current_user] = _override(user_b_id, registered)
        res_me = await client.get("/api/v1/auth/me")
        runner.assert_true(res_me.json().get("notification_email") == registered,
                           "/auth/me exposes the registered address")

    app.dependency_overrides.pop(get_current_user, None)
    action_engine.get_provider = _orig_get_provider


async def _standalone() -> int:
    runner = TestRunner()
    print("\n🧩 STARTING CYBERGUARD PHASE 6-7 TEST SUITE\n" + "=" * 60)
    await run_phase_6_7_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
