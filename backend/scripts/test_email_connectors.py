"""Phase 1-2 suite: Gmail connector, OAuth flow, encrypted token vault.

Covers:
- honest provider capability registry (Gmail enabled/coming-soon; others declared)
- POST /connectors/gmail/authorize (auth required, state row, Google URL shape)
- Gmail callback success with mocked Google token/profile responses
  (connector stored, tokens encrypted, plaintext absent, safe redirect)
- invalid/expired OAuth state → safe error redirect
- listing returns only the caller's connectors
- connector test via token manager with mocked Gmail profile
- disconnect clears token fields and marks revoked
- missing CONNECTOR_TOKEN_KEY produces a clear failure, not silent success

RLS cross-user isolation for connectors is verified on PostgreSQL in
scripts/test_rls_pg.py (Suite 10); SQLite has no RLS.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
from sqlalchemy import select

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.core.config import get_settings  # noqa: E402
from app.core.crypto import encrypt_secret  # noqa: E402
from app.core.security import get_current_user  # noqa: E402
from app.db.models import ConnectorOAuthState, EmailConnectorAccount  # noqa: E402
from app.db.session import async_session_maker  # noqa: E402
from app.main import app  # noqa: E402


class TestRunner:
    """Minimal runner matching scripts/run_all_tests.py conventions."""

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
            print("\033[32mALL EMAIL CONNECTOR TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


def _user(uid: str):
    return SimpleNamespace(id=uid, email=f"{uid}@cyberguard.test", full_name="Connector Tester", username=None, account_type="user")


async def run_email_connector_tests(runner: TestRunner) -> None:
    settings = get_settings()
    _backup = {
        "GOOGLE_GMAIL_CLIENT_ID": settings.GOOGLE_GMAIL_CLIENT_ID,
        "GOOGLE_GMAIL_CLIENT_SECRET": settings.GOOGLE_GMAIL_CLIENT_SECRET,
        "CONNECTOR_TOKEN_KEY": settings.CONNECTOR_TOKEN_KEY,
        "FRONTEND_CONNECTORS_URL": settings.FRONTEND_CONNECTORS_URL,
    }

    from cryptography.fernet import Fernet

    settings.GOOGLE_GMAIL_CLIENT_ID = "test-client-id.apps.googleusercontent.com"
    settings.GOOGLE_GMAIL_CLIENT_SECRET = "test-client-secret"
    settings.CONNECTOR_TOKEN_KEY = Fernet.generate_key().decode()
    settings.FRONTEND_CONNECTORS_URL = "http://testserver/email-connectors"

    user_a_id = f"conn-a-{uuid.uuid4().hex[:8]}"
    user_b_id = f"conn-b-{uuid.uuid4().hex[:8]}"

    def _override(user_id):
        async def _fn():
            return _user(user_id)

        return _fn

    # Mock the Google side: token exchange + profile.
    import app.services.connectors.oauth_service as oauth_service
    from app.services.email_providers.gmail import gmail_provider

    async def _fake_exchange(code: str) -> dict:
        return {
            "access_token": "ya29.fake-access-token-for-tests",
            "refresh_token": "1//fake-refresh-token-for-tests",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.modify",
        }

    async def _fake_profile(access_token: str) -> dict:
        return {
            "email_address": f"{user_a_id}@gmail.com",
            "messages_total": 1234,
            "threads_total": 900,
        }

    import app.services.connectors.token_manager as token_manager

    async def _fake_refresh(refresh_token: str) -> dict:
        return {
            "access_token": "ya29.fresh-access-token-after-refresh",
            "expires_in": 3600,
        }

    _orig_exchange = oauth_service._exchange_code
    _orig_profile = gmail_provider.get_profile
    _orig_refresh = token_manager._refresh_access_token
    oauth_service._exchange_code = _fake_exchange
    gmail_provider.get_profile = _fake_profile
    token_manager._refresh_access_token = _fake_refresh

    try:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60, follow_redirects=False) as client:

            # ------------------------------------------------------------
            # 11.1 Honest capability registry
            # ------------------------------------------------------------
            print("\n[Suite 11.1] Provider capability registry (honest)")
            res = await client.get("/api/v1/connectors/capabilities")
            runner.assert_true(res.status_code == 200, "GET /connectors/capabilities returns 200")
            caps = {item["provider"]: item for item in res.json()["items"]}
            runner.assert_true(
                set(caps) == {"gmail", "outlook", "yahoo", "icloud"},
                "Registry covers gmail/outlook/yahoo/icloud",
            )
            runner.assert_true(caps["gmail"]["status"] in ("enabled", "coming_soon"), "Gmail is enabled or coming soon")
            runner.assert_true(caps["outlook"]["status"] == "coming_soon", "Outlook declared coming soon")
            runner.assert_true(caps["yahoo"]["status"] == "unsupported", "Yahoo declared unsupported")
            runner.assert_true(caps["icloud"]["status"] == "unsupported", "iCloud declared unsupported")
            runner.assert_true(caps["yahoo"]["capabilities"] is None, "Unsupported providers declare no capabilities")

            # ------------------------------------------------------------
            # 11.2 Authorize endpoint
            # ------------------------------------------------------------
            print("\n[Suite 11.2] POST /connectors/gmail/authorize")
            res_noauth = await client.post("/api/v1/connectors/gmail/authorize")
            runner.assert_true(res_noauth.status_code in (401, 403), "Authorize requires authentication", f"status={res_noauth.status_code}")

            app.dependency_overrides[get_current_user] = _override(user_a_id)

            res = await client.post("/api/v1/connectors/gmail/authorize", json={})
            runner.assert_true(res.status_code == 200, "Authorize returns 200", f"status={res.status_code}")
            url = res.json().get("authorization_url", "")
            runner.assert_true(url.startswith("https://accounts.google.com/o/oauth2/v2/auth"), "Returns Google authorization URL")
            runner.assert_true("access_type=offline" in url, "URL requests offline access")
            runner.assert_true("gmail.modify" in url, "URL scopes include gmail.modify")
            runner.assert_true("prompt=consent" in url, "URL forces consent")
            runner.assert_true("state=" in url, "URL carries state")
            runner.assert_true("ya29" not in url and "access_token" not in url, "URL carries no token material")

            state_param = url.split("state=")[1].split("&")[0]
            async with async_session_maker() as db:
                row = (await db.execute(select(ConnectorOAuthState).where(ConnectorOAuthState.state == state_param))).scalar_one_or_none()
                runner.assert_true(row is not None, "Authorize persisted a single-use state row")
                runner.assert_true(row is not None and row.owner_user_id == user_a_id, "State row is bound to the caller")

            # ------------------------------------------------------------
            # 11.3 Callback success (mocked Google)
            # ------------------------------------------------------------
            print("\n[Suite 11.3] Gmail callback success (mocked Google)")
            res = await client.get(f"/api/v1/connectors/gmail/callback?code=test-code&state={state_param}")
            location = res.headers.get("location", "")
            runner.assert_true(res.status_code in (301, 302, 303, 307), "Callback redirects", f"status={res.status_code}")
            runner.assert_true(
                "status=success" in location and "connected=gmail" in location,
                "Callback redirects to frontend success URL",
                f"location={location}",
            )
            runner.assert_true("ya29" not in location and "refresh_token" not in location, "Redirect contains no tokens")

            async with async_session_maker() as db:
                rows = (
                    await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.owner_user_id == user_a_id))
                ).scalars().all()
                runner.assert_true(len(rows) == 1, "Connector account stored")
                conn = rows[0] if rows else None
                if conn:
                    runner.assert_true(conn.provider_email == f"{user_a_id}@gmail.com", "Provider email resolved from Gmail profile")
                    runner.assert_true(conn.status == "connected", "Connector status is connected")
                    runner.assert_true(bool(conn.access_token_enc and conn.refresh_token_enc), "Tokens stored encrypted")
                    runner.assert_true(
                        "fake-access-token" not in (conn.access_token_enc or "")
                        and "fake-refresh-token" not in (conn.refresh_token_enc or ""),
                        "Plaintext tokens absent from database",
                    )

            # State row is single-use: replaying must fail safely.
            res_replay = await client.get(f"/api/v1/connectors/gmail/callback?code=test-code&state={state_param}")
            runner.assert_true(
                "status=error" in (res_replay.headers.get("location", "") or "") and "invalid_state" in res_replay.headers.get("location", ""),
                "Replayed/unknown state redirects to safe error",
                f"location={res_replay.headers.get('location')}",
            )

            # ------------------------------------------------------------
            # 11.4 Invalid/expired state → safe error redirect
            # ------------------------------------------------------------
            print("\n[Suite 11.4] Callback with invalid state")
            res = await client.get("/api/v1/connectors/gmail/callback?code=x&state=bogus-state-value")
            runner.assert_true(res.status_code in (301, 302, 303, 307), "Invalid state redirects (no 500)")
            runner.assert_true("status=error" in (res.headers.get("location", "") or ""), "Invalid state redirects to error status")

            # Missing CONNECTOR_TOKEN_KEY during callback → clear server_configuration reason
            _saved_key = settings.CONNECTOR_TOKEN_KEY
            settings.CONNECTOR_TOKEN_KEY = ""
            fresh = await client.post("/api/v1/connectors/gmail/authorize", json={})
            state2 = fresh.json()["authorization_url"].split("state=")[1].split("&")[0]
            res = await client.get(f"/api/v1/connectors/gmail/callback?code=test-code&state={state2}")
            runner.assert_true(
                "reason=server_configuration" in (res.headers.get("location", "") or ""),
                "Missing CONNECTOR_TOKEN_KEY yields explicit server_configuration error",
                f"location={res.headers.get('location')}",
            )
            settings.CONNECTOR_TOKEN_KEY = _saved_key

            # ------------------------------------------------------------
            # 11.5 Listing returns only caller's connectors
            # ------------------------------------------------------------
            print("\n[Suite 11.5] Connector listing isolation (owner filter)")
            # Create a connector for user B directly.
            async with async_session_maker() as db:
                db.add(
                    EmailConnectorAccount(
                        id=f"conn-b-row-{uuid.uuid4().hex[:6]}",
                        owner_user_id=user_b_id,
                        provider="gmail",
                        provider_email=f"{user_b_id}@gmail.com",
                        status="connected",
                    )
                )
                await db.commit()

            app.dependency_overrides[get_current_user] = _override(user_b_id)
            res_b = await client.get("/api/v1/connectors")
            b_ids = [item["id"] for item in res_b.json()["items"]]
            runner.assert_true(
                all(i.startswith("conn-b-row") for i in b_ids) and len(b_ids) >= 1,
                "User B sees only their own connector(s)",
                f"ids={b_ids}",
            )

            app.dependency_overrides[get_current_user] = _override(user_a_id)
            res_a = await client.get("/api/v1/connectors")
            a_items = res_a.json()["items"]
            runner.assert_true(
                all(i["provider_email"] == f"{user_a_id}@gmail.com" for i in a_items) and len(a_items) >= 1,
                "User A sees only their own connector(s)",
            )

            # ------------------------------------------------------------
            # 11.6 Connector test via token manager (mocked Gmail API)
            # ------------------------------------------------------------
            print("\n[Suite 11.6] Connector connection test")
            connector_id = a_items[0]["id"]
            # Force a refresh: backdate the stored access token expiry.
            async with async_session_maker() as db:
                row = (await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_id))).scalar_one()
                row.access_token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
                await db.commit()

            res = await client.post(f"/api/v1/connectors/{connector_id}/test")
            runner.assert_true(res.status_code == 200, "POST /connectors/{id}/test returns 200", f"status={res.status_code}")
            data = res.json()
            runner.assert_true(data.get("ok") is True, "Connection test succeeds via token manager", f"data={data}")
            runner.assert_true(data.get("email_address") == f"{user_a_id}@gmail.com", "Test reports the mailbox identity")

            async with async_session_maker() as db:
                row = (await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_id))).scalar_one()
                exp = row.access_token_expires_at
                if exp is not None and exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                runner.assert_true(
                    exp is not None and exp > datetime.now(timezone.utc),
                    "Token manager persisted a fresh encrypted access token",
                )

            # ------------------------------------------------------------
            # 11.7 Disconnect clears token material, marks revoked
            # ------------------------------------------------------------
            print("\n[Suite 11.7] Disconnect")
            res = await client.delete(f"/api/v1/connectors/{connector_id}")
            runner.assert_true(res.status_code == 200, "DELETE /connectors/{id} returns 200", f"status={res.status_code}")
            runner.assert_true(res.json().get("status") == "revoked", "Disconnect marks connector revoked")
            async with async_session_maker() as db:
                row = (await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == connector_id))).scalar_one()
                runner.assert_true(
                    row.access_token_enc is None and row.refresh_token_enc is None,
                    "Disconnect cleared encrypted token fields",
                )

            # Cross-user access must 404 even for existing rows.
            b_connector_id = b_ids[0]
            res_a_get_b = await client.post(f"/api/v1/connectors/{b_connector_id}/test")
            runner.assert_true(res_a_get_b.status_code == 404, "User A cannot test user B's connector (404)")
            res_a_del_b = await client.delete(f"/api/v1/connectors/{b_connector_id}")
            runner.assert_true(res_a_del_b.status_code == 404, "User A cannot delete user B's connector (404)")

        app.dependency_overrides.pop(get_current_user, None)

        # ------------------------------------------------------------
        # 11.8 Missing CONNECTOR_TOKEN_KEY → clear error, not silent failure
        # ------------------------------------------------------------
        print("\n[Suite 11.8] Missing CONNECTOR_TOKEN_KEY fails loudly")
        real_key = settings.CONNECTOR_TOKEN_KEY
        settings.CONNECTOR_TOKEN_KEY = ""
        try:
            from app.core.crypto import encrypt_secret

            encrypt_secret("should-fail")
            runner.assert_true(False, "encrypt_secret raises without CONNECTOR_TOKEN_KEY", "no error raised")
        except RuntimeError as exc:
            runner.assert_true(
                "CONNECTOR_TOKEN_KEY is required" in str(exc),
                "encrypt_secret raises with a clear message",
                str(exc),
            )
        finally:
            settings.CONNECTOR_TOKEN_KEY = real_key

    finally:
        oauth_service._exchange_code = _orig_exchange
        gmail_provider.get_profile = _orig_profile
        token_manager._refresh_access_token = _orig_refresh
        for key, value in _backup.items():
            setattr(settings, key, value)


async def _standalone() -> int:
    runner = TestRunner()
    print("\n📧 STARTING CYBERGUARD EMAIL CONNECTOR TEST SUITE\n" + "=" * 60)
    await run_email_connector_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
