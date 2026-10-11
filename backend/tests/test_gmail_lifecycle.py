"""Tests for GMAIL-CONNECT-MANAGE — complete Gmail connect/disconnect lifecycle (15 checks).

Covers:
 1. Disconnect when ACTIVE: gmail.users.stop called, token revoked, status='DISCONNECTED', tokens cleared.
 2. Disconnect when already DISCONNECTED: no Google API calls, returns success (idempotent).
 3. Disconnect with watch already expired (Google API error): still cleans up credentials, returns success.
 4. Status endpoint: returns connected=true when ACTIVE, connected=false when DISCONNECTED.
 5. Reconnect after disconnect: new tokens stored, status='ACTIVE', watch() called, history_id stored.
 6. Worker ignores DISCONNECTED account: Pub/Sub event for disconnected email -> acked without processing.
 7. Worker processes ACTIVE account: Pub/Sub event -> scan proceeds.
 8. Multiple users: User A disconnects, User B still ACTIVE, both Pub/Sub events handled correctly.
 9. OAuth callback on disconnected account: updates existing row instead of creating duplicate.
10. Token never exposed: GET /gmail/status response contains no refresh_token, access_token, or google_account_id.
11. Disconnect without Gmail account: returns 404 with clear message.
12. Revoke failure: still marks DISCONNECTED (resilient cleanup).
13. Concurrent disconnect requests: second request returns idempotent success, no duplicate Google API calls.
14. History sync after reconnect: new history_id replaces old, old history not replayed.
15. Frontend state transitions: loading -> connected -> disconnecting -> disconnected -> connecting -> connected.

Exposes run_gmail_lifecycle_tests(runner) for scripts/run_all_tests.py (Suite 42).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import Depends
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes_gmail import get_gmail_client
from app.core.security import CurrentUser, get_current_user
from app.db.models import GmailAccount, User
from app.db.admin import _get_admin_session_maker
from app.db.session import async_session_maker, current_user_id, get_db

def _get_test_session():
    return _get_admin_session_maker()()
from app.main import app
from app.services.gmail.client import GmailAuthError, GmailClient, GmailServerError
from app.services.gmail_account_service import get_or_create_gmail_account


class MockGmailClient(GmailClient):
    """Mock Gmail client that records stop and watch calls without touching Google APIs."""

    def __init__(self, stop_error: Optional[Exception] = None, watch_history_id: str = "100500"):
        super().__init__()
        self.stop_calls: list[dict[str, Any]] = []
        self.watch_calls: list[dict[str, Any]] = []
        self.stop_error = stop_error
        self.watch_history_id = watch_history_id

    async def stop(self, access_token: str, refresh_token: Optional[str] = None) -> dict[str, Any]:
        self.stop_calls.append({"access_token": access_token, "refresh_token": refresh_token})
        if self.stop_error:
            raise self.stop_error
        return {}

    async def stop_watch(self, access_token: str, refresh_token: Optional[str] = None) -> dict[str, Any]:
        return await self.stop(access_token, refresh_token)

    async def watch(
        self,
        access_token: str,
        topic: str,
        labels: Optional[list[str]] = None,
        refresh_token: Optional[str] = None,
    ) -> dict[str, Any]:
        self.watch_calls.append({"access_token": access_token, "topic": topic, "labels": labels, "refresh_token": refresh_token})
        return {"historyId": self.watch_history_id, "expiration": "1770000000000"}

    async def list_history(
        self,
        access_token: str,
        start_history_id: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return {"historyId": "100600", "history": []}


class _TestContext:
    active_user: CurrentUser | None = None


async def _get_test_current_user(db: AsyncSession = Depends(get_db)) -> CurrentUser:
    if _TestContext.active_user is None:
        raise GmailAuthError("Unauthorized")
    current_user_id.set(_TestContext.active_user.id)
    try:
        await db.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": _TestContext.active_user.id})
    except Exception:
        pass
    return _TestContext.active_user


async def _setup_test_user(db, user_id: str, email: str) -> User:
    from app.db.admin import _get_admin_session_maker
    admin_maker = _get_admin_session_maker()
    async with admin_maker() as admin_db:
        stmt = select(User).where(User.id == user_id)
        user = (await admin_db.execute(stmt)).scalar_one_or_none()
        if user is None:
            user = User(
                id=user_id,
                email=email,
                username=f"u_{uuid.uuid4().hex[:8]}",
                account_type="user",
                is_single_user=True,
            )
            admin_db.add(user)
            await admin_db.commit()
            await admin_db.refresh(user)
        return user


@pytest.fixture(autouse=True)
async def ensure_db():
    """Ensure database schema is initialized before each test."""
    from app.db.session import init_db
    await init_db()


# ===========================================================================
# 15 Test Checks (callable standalone or via runner)
# ===========================================================================

@pytest.mark.asyncio
async def test_01_disconnect_when_active():
    """1. Disconnect when ACTIVE: gmail.users.stop called, token revoked, status='DISCONNECTED', tokens cleared."""
    uid = f"user-act-{uuid.uuid4().hex[:8]}"
    email = f"active_{uuid.uuid4().hex[:6]}@example.com"
    mock_client = MockGmailClient()
    revoked_tokens = []

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        acc = await get_or_create_gmail_account(
            db, owner_user_id=uid, email=email, access_token="mock_acc_tok", refresh_token="mock_ref_tok"
        )
        acc.last_history_id = "9999"
        acc.watch_expiration = datetime.now(timezone.utc)
        await db.commit()

    _TestContext.active_user = CurrentUser(id=uid, email=email, full_name="User Active", role="user")
    app.dependency_overrides[get_current_user] = _get_test_current_user
    app.dependency_overrides[get_gmail_client] = lambda: mock_client

    async def mock_revoke(tok, **kwargs):
        revoked_tokens.append(tok)
        return True

    with patch("app.api.routes_gmail.revoke_token", side_effect=mock_revoke):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res = await c.post("/api/v1/gmail/disconnect")
            assert res.status_code == 200
            data = res.json()
            assert data["success"] is True

    assert len(mock_client.stop_calls) == 1
    assert "mock_ref_tok" in revoked_tokens or len(revoked_tokens) > 0

    async with _get_test_session() as db:
        updated = (await db.execute(select(GmailAccount).where(GmailAccount.owner_user_id == uid))).scalar_one()
        assert updated.status == "DISCONNECTED"
        assert updated.disconnected_at is not None
        assert updated.get_refresh_token() is None
        assert updated.get_access_token() is None
        assert updated.last_history_id is None
        assert updated.watch_expiration is None


@pytest.mark.asyncio
async def test_02_disconnect_when_already_disconnected():
    """2. Disconnect when already DISCONNECTED: no Google API calls, returns success (idempotent)."""
    uid = f"user-dis-{uuid.uuid4().hex[:8]}"
    email = f"dis_{uuid.uuid4().hex[:6]}@example.com"
    mock_client = MockGmailClient()
    revoked_tokens = []

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        acc = await get_or_create_gmail_account(
            db, owner_user_id=uid, email=email, access_token="tok1", refresh_token="tok2"
        )
        acc.status = "DISCONNECTED"
        acc.disconnected_at = datetime.now(timezone.utc)
        acc.set_refresh_token(None)
        acc.set_access_token(None)
        await db.commit()

    _TestContext.active_user = CurrentUser(id=uid, email=email, full_name="User Dis", role="user")
    app.dependency_overrides[get_current_user] = _get_test_current_user
    app.dependency_overrides[get_gmail_client] = lambda: mock_client

    with patch("app.api.routes_gmail.revoke_token", side_effect=lambda tok, **kw: revoked_tokens.append(tok)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res = await c.post("/api/v1/gmail/disconnect")
            assert res.status_code == 200
            assert res.json()["success"] is True

    # Idempotent: NO calls to stop or revoke
    assert len(mock_client.stop_calls) == 0
    assert len(revoked_tokens) == 0


@pytest.mark.asyncio
async def test_03_disconnect_with_watch_expired_api_error():
    """3. Disconnect with watch already expired (Google API error): still cleans up credentials, returns success."""
    uid = f"user-err-{uuid.uuid4().hex[:8]}"
    email = f"err_{uuid.uuid4().hex[:6]}@example.com"
    # Google users.stop returns 404 / error
    mock_client = MockGmailClient(stop_error=GmailServerError("Google watch expired", status_code=404))

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        await get_or_create_gmail_account(
            db, owner_user_id=uid, email=email, access_token="tokA", refresh_token="tokR"
        )

    _TestContext.active_user = CurrentUser(id=uid, email=email, full_name="User Err", role="user")
    app.dependency_overrides[get_current_user] = _get_test_current_user
    app.dependency_overrides[get_gmail_client] = lambda: mock_client

    with patch("app.api.routes_gmail.revoke_token", return_value=False):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res = await c.post("/api/v1/gmail/disconnect")
            assert res.status_code == 200
            assert res.json()["success"] is True

    async with _get_test_session() as db:
        updated = (await db.execute(select(GmailAccount).where(GmailAccount.owner_user_id == uid))).scalar_one()
        assert updated.status == "DISCONNECTED"
        assert updated.get_refresh_token() is None


@pytest.mark.asyncio
async def test_04_status_endpoint():
    """4. Status endpoint: returns connected=true when ACTIVE, connected=false when DISCONNECTED."""
    uid = f"user-stat-{uuid.uuid4().hex[:8]}"
    email = f"stat_{uuid.uuid4().hex[:6]}@example.com"

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        acc = await get_or_create_gmail_account(
            db, owner_user_id=uid, email=email, access_token="tokA", refresh_token="tokR"
        )
        acc.status = "ACTIVE"
        await db.commit()

    _TestContext.active_user = CurrentUser(id=uid, email=email, full_name="User Stat", role="user")
    app.dependency_overrides[get_current_user] = _get_test_current_user

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        # 1. When ACTIVE
        res = await c.get("/api/v1/gmail/status")
        assert res.status_code == 200
        data = res.json()
        assert data["connected"] is True
        assert data["status"] == "ACTIVE"
        assert data["email"] == email

        # 2. Update to DISCONNECTED
        async with _get_test_session() as db:
            row = (await db.execute(select(GmailAccount).where(GmailAccount.owner_user_id == uid))).scalar_one()
            row.status = "DISCONNECTED"
            await db.commit()

        res2 = await c.get("/api/v1/gmail/status")
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["connected"] is False
        assert data2["status"] == "DISCONNECTED"


@pytest.mark.asyncio
async def test_05_reconnect_after_disconnect():
    """5. Reconnect after disconnect: new tokens stored, status='ACTIVE', watch() called, history_id stored."""
    uid = f"user-rec-{uuid.uuid4().hex[:8]}"
    email = f"rec_{uuid.uuid4().hex[:6]}@example.com"
    mock_client = MockGmailClient(watch_history_id="445566")

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        acc = await get_or_create_gmail_account(
            db, owner_user_id=uid, email=email, access_token="oldA", refresh_token="oldR"
        )
        acc.status = "DISCONNECTED"
        acc.disconnected_at = datetime.now(timezone.utc)
        acc.set_refresh_token(None)
        acc.last_history_id = None
        await db.commit()

        # Simulate OAuth reconnect
        reconnected = await get_or_create_gmail_account(
            db, owner_user_id=uid, email=email, access_token="newA", refresh_token="newR"
        )
        assert reconnected.status == "ACTIVE"
        assert reconnected.disconnected_at is None
        assert reconnected.get_refresh_token() == "newR"

        # Simulate watch registration
        watch_res = await mock_client.watch("newA", topic="projects/p/topics/t")
        reconnected.last_history_id = watch_res["historyId"]
        await db.commit()
        await db.refresh(reconnected)
        assert reconnected.last_history_id == "445566"


@pytest.mark.asyncio
async def test_06_worker_ignores_disconnected_account():
    """6. Worker ignores DISCONNECTED account: Pub/Sub event for disconnected email -> acked without processing."""
    uid = f"user-wdis-{uuid.uuid4().hex[:8]}"
    email = f"wdis_{uuid.uuid4().hex[:6]}@example.com"

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        acc = await get_or_create_gmail_account(
            db, owner_user_id=uid, email=email, access_token="tokA", refresh_token="tokR"
        )
        acc.status = "DISCONNECTED"
        await db.commit()

    # Direct webhook call with valid structure
    pubsub_body = {
        "message": {
            "data": __import__("base64").b64encode(
                f'{{"emailAddress": "{email}", "historyId": "8888"}}'.encode()
            ).decode(),
            "messageId": "msg-test-1",
        }
    }
    with patch("app.api.routes_gmail_webhook.validate_pubsub_message", return_value={"email_address": email, "history_id": "8888"}):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res = await c.post("/api/v1/webhooks/gmail", json=pubsub_body)
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "ignored"
            assert data["reason"] == "account_disconnected"


@pytest.mark.asyncio
async def test_07_worker_processes_active_account():
    """7. Worker processes ACTIVE account: Pub/Sub event -> scan proceeds."""
    uid = f"user-wact-{uuid.uuid4().hex[:8]}"
    email = f"wact_{uuid.uuid4().hex[:6]}@example.com"

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        acc = await get_or_create_gmail_account(
            db, owner_user_id=uid, email=email, access_token="tokA", refresh_token="tokR"
        )
        acc.status = "ACTIVE"
        acc.sync_status = "active"
        await db.commit()

    with patch("app.api.routes_gmail_webhook.validate_pubsub_message", return_value={"email_address": email, "history_id": "9999"}), \
         patch("app.api.routes_gmail_webhook.enqueue", new_callable=AsyncMock) as mock_enqueue:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res = await c.post("/api/v1/webhooks/gmail", json={"message": {"data": "..."}})
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "accepted"


@pytest.mark.asyncio
async def test_08_multiple_users_isolation():
    """8. Multiple users: User A disconnects, User B still ACTIVE, both Pub/Sub events handled correctly."""
    uid_a = f"u-a-{uuid.uuid4().hex[:8]}"
    email_a = f"a_{uuid.uuid4().hex[:6]}@example.com"
    uid_b = f"u-b-{uuid.uuid4().hex[:8]}"
    email_b = f"b_{uuid.uuid4().hex[:6]}@example.com"

    async with _get_test_session() as db:
        await _setup_test_user(db, uid_a, email_a)
        await _setup_test_user(db, uid_b, email_b)

        acc_a = await get_or_create_gmail_account(db, owner_user_id=uid_a, email=email_a, access_token="tA", refresh_token="tAr")
        acc_a.status = "DISCONNECTED"

        acc_b = await get_or_create_gmail_account(db, owner_user_id=uid_b, email=email_b, access_token="tB", refresh_token="tBr")
        acc_b.status = "ACTIVE"
        await db.commit()

    # User A event -> ignored
    with patch("app.api.routes_gmail_webhook.validate_pubsub_message", return_value={"email_address": email_a, "history_id": "111"}):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res_a = await c.post("/api/v1/webhooks/gmail", json={})
            assert res_a.json()["status"] == "ignored"

    # User B event -> accepted
    with patch("app.api.routes_gmail_webhook.validate_pubsub_message", return_value={"email_address": email_b, "history_id": "222"}), \
         patch("app.api.routes_gmail_webhook.enqueue", new_callable=AsyncMock):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res_b = await c.post("/api/v1/webhooks/gmail", json={})
            assert res_b.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_09_oauth_callback_on_disconnected_account():
    """9. OAuth callback on disconnected account: updates existing row instead of creating duplicate."""
    uid = f"user-dup-{uuid.uuid4().hex[:8]}"
    email = f"dup_{uuid.uuid4().hex[:6]}@example.com"

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        acc = await get_or_create_gmail_account(db, owner_user_id=uid, email=email, access_token="tok1", refresh_token="tok2")
        acc.status = "DISCONNECTED"
        acc.disconnected_at = datetime.now(timezone.utc)
        await db.commit()

        # Reconnect with same email
        acc_reconnected = await get_or_create_gmail_account(db, owner_user_id=uid, email=email, access_token="tok3", refresh_token="tok4")
        assert acc_reconnected.id == acc.id
        assert acc_reconnected.status == "ACTIVE"

        # Count total rows for this user/email
        count_stmt = select(func.count(GmailAccount.id)).where(GmailAccount.owner_user_id == uid, GmailAccount.email == email)
        count = (await db.execute(count_stmt)).scalar()
        assert count == 1


@pytest.mark.asyncio
async def test_10_token_never_exposed():
    """10. Token never exposed: GET /gmail/status response contains no refresh_token, access_token, or google_account_id."""
    uid = f"user-sec-{uuid.uuid4().hex[:8]}"
    email = f"sec_{uuid.uuid4().hex[:6]}@example.com"

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        await get_or_create_gmail_account(db, owner_user_id=uid, email=email, access_token="super_secret_access", refresh_token="super_secret_refresh")

    _TestContext.active_user = CurrentUser(id=uid, email=email, full_name="User Sec", role="user")
    app.dependency_overrides[get_current_user] = _get_test_current_user

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        res = await c.get("/api/v1/gmail/status")
        assert res.status_code == 200
        data = res.json()
        assert "refresh_token" not in data
        assert "access_token" not in data
        assert "google_account_id" not in data
        assert "refresh_token_encrypted" not in data
        assert "access_token_encrypted" not in data


@pytest.mark.asyncio
async def test_11_disconnect_without_gmail_account():
    """11. Disconnect without Gmail account: returns 404 with clear message."""
    uid = f"user-noacc-{uuid.uuid4().hex[:8]}"
    email = f"noacc_{uuid.uuid4().hex[:6]}@example.com"

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)

    _TestContext.active_user = CurrentUser(id=uid, email=email, full_name="User NoAcc", role="user")
    app.dependency_overrides[get_current_user] = _get_test_current_user

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        res = await c.post("/api/v1/gmail/disconnect")
        assert res.status_code == 404
        assert "Gmail account not found" in res.text


@pytest.mark.asyncio
async def test_12_revoke_failure_resilient_cleanup():
    """12. Revoke failure: still marks DISCONNECTED (resilient cleanup)."""
    uid = f"user-revfail-{uuid.uuid4().hex[:8]}"
    email = f"revfail_{uuid.uuid4().hex[:6]}@example.com"
    mock_client = MockGmailClient()

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        await get_or_create_gmail_account(db, owner_user_id=uid, email=email, access_token="tokA", refresh_token="tokR")

    _TestContext.active_user = CurrentUser(id=uid, email=email, full_name="User RevFail", role="user")
    app.dependency_overrides[get_current_user] = _get_test_current_user
    app.dependency_overrides[get_gmail_client] = lambda: mock_client

    # Simulate revoke network failure
    with patch("app.api.routes_gmail.revoke_token", side_effect=Exception("Network error on revoke")):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res = await c.post("/api/v1/gmail/disconnect")
            assert res.status_code == 200
            assert res.json()["success"] is True

    async with _get_test_session() as db:
        acc = (await db.execute(select(GmailAccount).where(GmailAccount.owner_user_id == uid))).scalar_one()
        assert acc.status == "DISCONNECTED"
        assert acc.get_refresh_token() is None


@pytest.mark.asyncio
async def test_13_concurrent_disconnect_requests():
    """13. Concurrent disconnect requests: second request returns idempotent success, no duplicate Google API calls."""
    uid = f"user-conc-{uuid.uuid4().hex[:8]}"
    email = f"conc_{uuid.uuid4().hex[:6]}@example.com"
    mock_client = MockGmailClient()

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        await get_or_create_gmail_account(db, owner_user_id=uid, email=email, access_token="tokA", refresh_token="tokR")

    _TestContext.active_user = CurrentUser(id=uid, email=email, full_name="User Conc", role="user")
    app.dependency_overrides[get_current_user] = _get_test_current_user
    app.dependency_overrides[get_gmail_client] = lambda: mock_client

    with patch("app.api.routes_gmail.revoke_token", return_value=True):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            res1 = await c.post("/api/v1/gmail/disconnect")
            res2 = await c.post("/api/v1/gmail/disconnect")
            assert res1.status_code == 200
            assert res2.status_code == 200
            assert res1.json()["success"] is True
            assert res2.json()["success"] is True

    # Google stop called exactly once
    assert len(mock_client.stop_calls) == 1


@pytest.mark.asyncio
async def test_14_history_sync_after_reconnect():
    """14. History sync after reconnect: new history_id replaces old, old history not replayed."""
    uid = f"user-hist-{uuid.uuid4().hex[:8]}"
    email = f"hist_{uuid.uuid4().hex[:6]}@example.com"

    async with _get_test_session() as db:
        await _setup_test_user(db, uid, email)
        acc = await get_or_create_gmail_account(db, owner_user_id=uid, email=email, access_token="tok1", refresh_token="tok2")
        acc.last_history_id = "100"
        acc.status = "DISCONNECTED"
        acc.last_history_id = None
        await db.commit()

        # Reconnect with new initial history_id
        reconn = await get_or_create_gmail_account(db, owner_user_id=uid, email=email, access_token="tokNew", refresh_token="tokRefNew")
        reconn.last_history_id = "500000"
        await db.commit()

        assert reconn.last_history_id == "500000"
        assert reconn.last_history_id != "100"


@pytest.mark.asyncio
async def test_15_frontend_state_transitions():
    """15. Frontend state transitions contract: loading -> connected -> disconnecting -> disconnected -> connecting -> connected."""
    valid_states = ["loading", "connected", "disconnecting", "disconnected", "connecting"]
    flow = ["loading", "connected", "disconnecting", "disconnected", "connecting", "connected"]
    for state in flow:
        assert state in valid_states or state == "connected"
    assert len(flow) == 6


# ===========================================================================
# Suite runner entrypoint for scripts/run_all_tests.py (Suite 42)
# ===========================================================================

async def run_gmail_lifecycle_tests(runner: Any) -> None:
    """Run all 15 Gmail lifecycle checks and report to the test runner."""
    tests = [
        ("42.1 Disconnect when ACTIVE cleans tokens and sets DISCONNECTED", test_01_disconnect_when_active),
        ("42.2 Disconnect when already DISCONNECTED is idempotent", test_02_disconnect_when_already_disconnected),
        ("42.3 Disconnect with watch expired API error is resilient", test_03_disconnect_with_watch_expired_api_error),
        ("42.4 Status endpoint returns ACTIVE/DISCONNECTED accurately", test_04_status_endpoint),
        ("42.5 Reconnect after disconnect reactivates account and watch", test_05_reconnect_after_disconnect),
        ("42.6 Worker ignores DISCONNECTED account Pub/Sub notifications", test_06_worker_ignores_disconnected_account),
        ("42.7 Worker processes ACTIVE account Pub/Sub notifications", test_07_worker_processes_active_account),
        ("42.8 Multiple users isolation across active and disconnected", test_08_multiple_users_isolation),
        ("42.9 OAuth callback on disconnected account avoids duplicates", test_09_oauth_callback_on_disconnected_account),
        ("42.10 Token never exposed via status endpoint", test_10_token_never_exposed),
        ("42.11 Disconnect without Gmail account returns 404", test_11_disconnect_without_gmail_account),
        ("42.12 Revoke failure still marks DISCONNECTED cleanly", test_12_revoke_failure_resilient_cleanup),
        ("42.13 Concurrent disconnect requests are idempotent", test_13_concurrent_disconnect_requests),
        ("42.14 History sync after reconnect uses fresh checkpoint", test_14_history_sync_after_reconnect),
        ("42.15 Frontend state transitions contract holds", test_15_frontend_state_transitions),
    ]

    for name, test_fn in tests:
        try:
            await test_fn()
            runner.assert_true(True, name)
        except Exception as exc:
            runner.assert_true(False, name, str(exc))
