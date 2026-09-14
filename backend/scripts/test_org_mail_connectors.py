"""ORG-3 — Org mail server connectors test suite (Suite 19).

Covers:
1.  Server registration (Google Workspace / M365 / IMAP), duplicate names
2.  Connect (new + stored credentials) -> connected + connection log
3.  Graceful disconnect -> disconnected, credentials retained
4.  Fetch emails (mocked transport: 5 messages -> normalized shape)
5.  Quarantine -> log entry
6.  Per-server log grouping (server A stream never contains server B)
7.  Per-server settings (defaults, admin update, unknown key)
8.  RBAC: analyst blocked from admin actions; viewer blocked from settings
9.  Cross-org isolation: API (403) + raw RLS (0 rows)
10. Credential encryption at rest (Fernet, no plaintext)

Run via run_all_tests.py (Suite 19) or standalone:
    uv run python scripts/test_org_mail_connectors.py
"""

import asyncio
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.security import CurrentUser, get_current_user
from app.db.session import async_session_maker, current_user_id, engine
from app.main import app
from _rls import create_user_admin


class _Identity:
    user: CurrentUser | None = None


async def _mock_get_current_user() -> CurrentUser:
    if _Identity.user is None:
        raise RuntimeError("test identity not set")
    current_user_id.set(_Identity.user.id)  # RLS identity, as in production
    return _Identity.user


def _runner_shim(runner):
    class _R:
        def __init__(self):
            self.passed = 0
            self.failed = 0

        def assert_true(self, condition, name, details=""):
            runner.assert_true(condition, name, details)

    return _R()


async def _ensure_user(db, user_id: str, email: str, full_name: str) -> None:
    from sqlalchemy import select

    from app.db.models import User

    existing = await db.execute(select(User).where(User.id == user_id))
    if existing.scalar_one_or_none() is not None:
        return
    await db.commit()
    current_user_id.set(user_id)
    db.add(User(id=user_id, email=email, full_name=full_name, is_single_user=True))
    await db.commit()
    current_user_id.set(None)


GOOGLE_CREDS = {
    "service_account_key": "-----BEGIN PRIVATE KEY-----TESTKEY\nline2\n",
    "delegated_user": "scanner@corp.example",
}
M365_CREDS = {"client_id": "cid-123", "client_secret": "cs-secret", "tenant_id": "tid-9"}
IMAP_CREDS = {"host": "mail.corp.example", "port": 993, "username": "scan@corp.example", "password": "app-pass-1"}


class _StubTransport:
    """Test transport: verifies, yields 5 normalized-source messages."""

    mode = "stub"

    async def verify(self, provider_type, credentials):
        return {"simulated": False, "mode": "stub", "provider": provider_type}

    async def fetch_recent_emails(self, provider_type, credentials, limit):
        return [
            {"message_id": f"msg-{i}", "sender": f"sender{i}@example.com",
             "subject": f"Subject {i}", "snippet": f"body {i}"}
            for i in range(min(5, limit))
        ]

    async def quarantine_email(self, provider_type, credentials, message_id):
        return {"simulated": False, "message_id": message_id, "quarantined": True}


async def run_org_mail_tests(runner) -> None:
    r = _runner_shim(runner)
    print("\n" + "-" * 60)
    print("ORG-3 Mail Connectors: servers, per-server logs/settings, RBAC")
    print("-" * 60)

    stamp = uuid.uuid4().hex[:8]
    admin = CurrentUser(id=f"orgm-admin-{stamp}", email=f"orgm-admin-{stamp}@cyberguard.test", full_name="Org M Admin")
    analyst = CurrentUser(id=f"orgm-analyst-{stamp}", email=f"orgm-analyst-{stamp}@cyberguard.test", full_name="Org M Analyst")
    viewer = CurrentUser(id=f"orgm-viewer-{stamp}", email=f"orgm-viewer-{stamp}@cyberguard.test", full_name="Org M Viewer")
    other_admin = CurrentUser(id=f"orgn-admin-{stamp}", email=f"orgn-admin-{stamp}@cyberguard.test", full_name="Org N Admin")

    async with async_session_maker() as db:
        for u in (admin, analyst, viewer, other_admin):
            await _ensure_user(db, u.id, u.email or "", u.full_name or "")

    app.dependency_overrides[get_current_user] = _mock_get_current_user

    from app.services.org_mail_connector_service import ORG_MAIL_TRANSPORTS

    original_transport = ORG_MAIL_TRANSPORTS["google_workspace"]
    ORG_MAIL_TRANSPORTS["google_workspace"] = _StubTransport()

    org_m = org_n = ""
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            _Identity.user = admin
            org_m = (await client.post("/api/v1/orgs", json={"name": f"Mail Org M {stamp}"})).json()["id"]
            _Identity.user = other_admin
            org_n = (await client.post("/api/v1/orgs", json={"name": f"Mail Org N {stamp}"})).json()["id"]
            _Identity.user = admin
            res_a = await client.post(f"/api/v1/orgs/{org_m}/members", json={"email": analyst.email, "role": "analyst"})
            res_v = await client.post(f"/api/v1/orgs/{org_m}/members", json={"email": viewer.email, "role": "viewer"})
            r.assert_true(res_a.status_code == 201 and res_v.status_code == 201, "Admin adds analyst + viewer")

            # ------------------------------------------------------------
            # 1. Create mail servers
            # ------------------------------------------------------------
            res = await client.post(f"/api/v1/org/{org_m}/mail-servers", json={
                "name": "Primary Gmail", "provider_type": "google_workspace", "credentials": GOOGLE_CREDS,
            })
            r.assert_true(res.status_code == 201, "Admin creates Google Workspace server (201)")
            server_a = res.json()
            r.assert_true(server_a["status"] == "connected", "Server connects immediately with credentials")
            r.assert_true(server_a["has_credentials"] is True, "has_credentials flagged (credentials never returned)")
            r.assert_true("service_account_key" not in res.text and "TESTKEY" not in res.text, "Response carries no credential material")

            res = await client.post(f"/api/v1/org/{org_m}/mail-servers", json={
                "name": "Legacy Exchange", "provider_type": "microsoft_365", "credentials": M365_CREDS,
            })
            server_b = res.json()
            r.assert_true(res.status_code == 201, "Admin creates Microsoft 365 server")

            res = await client.post(f"/api/v1/org/{org_m}/mail-servers", json={
                "name": "Relay IMAP", "provider_type": "imap_smtp", "credentials": IMAP_CREDS, "connect_now": False,
            })
            server_c = res.json()
            r.assert_true(res.status_code == 201 and server_c["status"] == "disconnected", "IMAP server created disconnected")

            res = await client.post(f"/api/v1/org/{org_m}/mail-servers", json={
                "name": "Primary Gmail", "provider_type": "google_workspace",
            })
            r.assert_true(res.status_code == 409, "Duplicate server name within org -> 409")

            res = await client.post(f"/api/v1/org/{org_m}/mail-servers", json={
                "name": "Bad Creds", "provider_type": "google_workspace",
                "credentials": {"service_account_key": "only-half"},
            })
            r.assert_true(res.status_code == 400, "Incomplete credentials -> 400")

            # ------------------------------------------------------------
            # 2. Connect / reconnect / rotate
            # ------------------------------------------------------------
            res = await client.post(f"/api/v1/org/{org_m}/mail-servers/{server_c['id']}/connect",
                                    json={"credentials": IMAP_CREDS})
            r.assert_true(res.status_code == 200 and res.json()["status"] == "connected", "IMAP server connects with credentials")

            res = await client.post(f"/api/v1/org/{org_m}/mail-servers/{server_c['id']}/disconnect", json={})
            r.assert_true(res.status_code == 200 and res.json()["status"] == "disconnected", "Disconnect succeeds")
            res = await client.post(f"/api/v1/org/{org_m}/mail-servers/{server_c['id']}/connect", json={})
            r.assert_true(res.status_code == 200 and res.json()["status"] == "connected", "Reconnect uses stored credentials")

            # ------------------------------------------------------------
            # 3. Graceful disconnect retains credentials
            # ------------------------------------------------------------
            res = await client.post(f"/api/v1/org/{org_m}/mail-servers/{server_c['id']}/disconnect", json={})
            r.assert_true(res.json()["detail"]["credentials_retained"] is True, "Graceful disconnect retains credentials")
            res = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_c['id']}")
            r.assert_true(res.json()["status"] == "disconnected" and res.json()["has_credentials"] is True,
                          "Disconnected server keeps its credential blob for reconnect")

            # ------------------------------------------------------------
            # 4-5. Fetch emails (mocked transport) + quarantine
            # ------------------------------------------------------------
            res = await client.post(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/fetch?limit=10")
            r.assert_true(res.status_code == 200 and res.json()["count"] == 5, "Stub transport yields 5 messages")
            messages = res.json()["messages"]
            r.assert_true(
                all(set(m) >= {"message_id", "sender", "subject", "snippet", "provider"} and m["provider"] == "google_workspace"
                    for m in messages),
                "Messages normalized to the common shape with provider tag",
            )

            res = await client.post(f"/api/v1/org/{org_m}/mail-servers/{server_c['id']}/fetch")
            r.assert_true(res.status_code == 400, "Fetch on disconnected server -> 400")

            res = await client.post(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/quarantine",
                                    json={"message_id": "msg-3"})
            r.assert_true(res.status_code == 200 and res.json()["status"] == "quarantined", "Quarantine succeeds")

            # ------------------------------------------------------------
            # 6. Per-server log grouping + filters
            # ------------------------------------------------------------
            res_a_logs = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/logs")
            r.assert_true(res_a_logs.status_code == 200, "GET per-server logs (analyst+)")
            logs_a = res_a_logs.json()
            r.assert_true(len(logs_a) >= 3, f"Server A stream has its own entries (got {len(logs_a)})")
            r.assert_true(all(l["mail_server_id"] == server_a["id"] for l in logs_a), "Server A stream only contains server A logs")

            res_b_logs = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_b['id']}/logs")
            logs_b = res_b_logs.json()
            ids_a = {l["id"] for l in logs_a}
            ids_b = {l["id"] for l in logs_b}
            r.assert_true(not (ids_a & ids_b), "Server B stream is fully disjoint from server A (per-server grouping)")

            r.assert_true(any(l["log_type"] == "quarantine" for l in logs_a), "Quarantine action produced a quarantine log entry")
            r.assert_true(any(l["log_type"] == "scan" for l in logs_a), "Fetch produced a scan log entry")

            res = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/logs?log_type=connection")
            r.assert_true(all(l["log_type"] == "connection" for l in res.json()), "log_type filter works")
            res = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/logs?from_date=1999-01-01T00:00:00Z")
            r.assert_true(len(res.json()) == len(logs_a), "from_date in the past keeps all entries")

            # ------------------------------------------------------------
            # 7. Per-server settings
            # ------------------------------------------------------------
            res = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/settings")
            r.assert_true(res.status_code == 200, "Analyst reads per-server settings")
            settings = res.json()["settings"]
            r.assert_true(
                settings.get("scan_interval_seconds") == 300 and settings.get("quarantine_enabled") is True
                and settings.get("quarantine_expiry_hours") == 24,
                "Default settings seeded per server",
            )

            res = await client.put(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/settings",
                                   json={"settings": {"scan_interval_seconds": 120, "auto_block_malicious_senders": True}})
            r.assert_true(res.status_code == 200 and res.json()["settings"]["scan_interval_seconds"] == 120,
                          "Admin updates settings")

            res = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_b['id']}/settings")
            r.assert_true(res.json()["settings"]["scan_interval_seconds"] == 300,
                          "Server B settings untouched by server A update (per-server isolation)")

            res = await client.put(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/settings",
                                   json={"settings": {"bogus_key": 1}})
            r.assert_true(res.status_code == 400, "Unknown setting key -> 400")

            # ------------------------------------------------------------
            # 8. RBAC
            # ------------------------------------------------------------
            _Identity.user = analyst
            res = await client.post(f"/api/v1/org/{org_m}/mail-servers", json={"name": "x", "provider_type": "imap_smtp"})
            r.assert_true(res.status_code == 403, "Analyst cannot create mail servers")
            res = await client.delete(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}")
            r.assert_true(res.status_code == 403, "Analyst cannot delete mail servers")
            res = await client.post(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/disconnect", json={})
            r.assert_true(res.status_code == 403, "Analyst cannot disconnect mail servers")
            res = await client.put(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/settings",
                                   json={"settings": {"scan_interval_seconds": 1}})
            r.assert_true(res.status_code == 403, "Analyst cannot update settings")

            _Identity.user = viewer
            res = await client.get(f"/api/v1/org/{org_m}/mail-servers")
            r.assert_true(res.status_code == 403, "Viewer cannot list mail servers (analyst+ surface)")
            res = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/settings")
            r.assert_true(res.status_code == 403, "Viewer cannot access settings (403)")
            res = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/logs")
            r.assert_true(res.status_code == 403, "Viewer cannot read per-server logs (analyst+ surface)")

            # ------------------------------------------------------------
            # 9. Cross-org isolation
            # ------------------------------------------------------------
            _Identity.user = other_admin
            res = await client.get(f"/api/v1/org/{org_m}/mail-servers")
            r.assert_true(res.status_code == 403, "Org N admin cannot list Org M servers (API layer)")
            res = await client.get(f"/api/v1/org/{org_m}/mail-servers/{server_a['id']}/logs")
            r.assert_true(res.status_code == 403, "Org N admin cannot read Org M server logs (API layer)")

            seen = await _rls_mail_server_count(org_m, other_admin.id)
            r.assert_true(seen == 0, "RLS: Org N user sees 0 Org M mail servers", f"seen={seen}")
            seen_admin = await _rls_mail_server_count(org_m, admin.id)
            r.assert_true(seen_admin >= 3, "RLS: Org M admin sees Org M mail servers", f"seen={seen_admin}")

            # ------------------------------------------------------------
            # 10. Credential encryption at rest
            # ------------------------------------------------------------
            blob = await _raw_credentials_blob(server_a["id"])
            r.assert_true(blob is not None and blob.startswith("gAAAA"), "Credentials stored Fernet-encrypted (gAAAA… prefix)")
            r.assert_true("TESTKEY" not in blob and "scanner@corp.example" not in blob,
                          "No plaintext credential material in the DB row")
    finally:
        ORG_MAIL_TRANSPORTS["google_workspace"] = original_transport
        app.dependency_overrides.pop(get_current_user, None)
        current_user_id.set(None)


async def _rls_mail_server_count(org_id: str, guc_user: str) -> int:
    async with engine.connect() as conn:
        await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": guc_user})
        return (
            await conn.execute(
                text("select count(*) from cyberguard.org_mail_servers where organization_id = :org"),
                {"org": org_id},
            )
        ).scalar()


async def _raw_credentials_blob(server_id: str) -> str | None:
    from app.db.admin import _get_admin_session_maker

    async with _get_admin_session_maker()() as db:
        row = (
            await db.execute(
                text("select credentials_encrypted from cyberguard.org_mail_servers where id = :id"),
                {"id": server_id},
            )
        ).scalar_one_or_none()
    return row


async def _standalone() -> int:
    class _Runner:
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
            print(f"\nORG-3: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n📮 CYBERGUARD ORG-3 MAIL CONNECTOR TESTS\n" + "=" * 60)
    await run_org_mail_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
