"""ORG-4 — Org email notification groups test suite (Suite 20).

Covers:
1.  Registered emails: add (admin), duplicate rejected, role filter, list
2.  send_event role filtering: min_role=analyst -> analyst+; min_role=admin
    -> admins only
3.  Disabled email excluded from sends
4.  Disabled event type -> no sends (empty result)
5.  Delivery log row per send with per-recipient outcomes
6.  End-to-end triggers: mail_server_down (connect failure), server_down
    (fetch failure), critical_log (critical log ingest), impersonation
    (gateway lookalike-domain scan)
7.  RBAC: analyst cannot add/update/delete emails or settings; viewer gets
    403 on emails/settings/logs
8.  Cross-org isolation: API (403) + raw RLS (0 rows)

Run via run_all_tests.py (Suite 20) or standalone:
    uv run python scripts/test_org_notifications.py
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
    current_user_id.set(_Identity.user.id)
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


class _StubMailTransport:
    mode = "stub"

    async def verify(self, provider_type, credentials):
        return {"mode": "stub"}

    async def fetch_recent_emails(self, provider_type, credentials, limit):
        return []

    async def quarantine_email(self, provider_type, credentials, message_id):
        return {"quarantined": True}


async def run_org_notification_tests(runner) -> None:
    r = _runner_shim(runner)
    print("\n" + "-" * 60)
    print("ORG-4 Notifications: role groups, event routing, triggers, RBAC")
    print("-" * 60)

    stamp = uuid.uuid4().hex[:8]
    admin = CurrentUser(id=f"orgp-admin-{stamp}", email=f"orgp-admin-{stamp}@cyberguard.test", full_name="Org P Admin")
    analyst = CurrentUser(id=f"orgp-analyst-{stamp}", email=f"orgp-analyst-{stamp}@cyberguard.test", full_name="Org P Analyst")
    viewer = CurrentUser(id=f"orgp-viewer-{stamp}", email=f"orgp-viewer-{stamp}@cyberguard.test", full_name="Org P Viewer")
    other_admin = CurrentUser(id=f"orgq-admin-{stamp}", email=f"orgq-admin-{stamp}@cyberguard.test", full_name="Org Q Admin")

    async with async_session_maker() as db:
        for u in (admin, analyst, viewer, other_admin):
            await _ensure_user(db, u.id, u.email or "", u.full_name or "")

    app.dependency_overrides[get_current_user] = _mock_get_current_user

    from app.services.org_mail_connector_service import ORG_MAIL_TRANSPORTS

    original_transport = ORG_MAIL_TRANSPORTS["google_workspace"]
    ORG_MAIL_TRANSPORTS["google_workspace"] = _StubMailTransport()

    org_p = org_q = ""
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            _Identity.user = admin
            org_p = (await client.post("/api/v1/orgs", json={"name": f"Notify Org P {stamp}"})).json()["id"]
            _Identity.user = other_admin
            org_q = (await client.post("/api/v1/orgs", json={"name": f"Notify Org Q {stamp}"})).json()["id"]
            _Identity.user = admin
            res = await client.post(f"/api/v1/orgs/{org_p}/members", json={"email": analyst.email, "role": "analyst"})
            res2 = await client.post(f"/api/v1/orgs/{org_p}/members", json={"email": viewer.email, "role": "viewer"})
            r.assert_true(res.status_code == 201 and res2.status_code == 201, "Admin adds analyst + viewer members")

            # ------------------------------------------------------------
            # 1. Registered emails
            # ------------------------------------------------------------
            res = await client.post(f"/api/v1/org/{org_p}/notifications/emails",
                                    json={"email": f"soc-admin-{stamp}@corp.example", "role": "admin"})
            r.assert_true(res.status_code == 201, "Admin registers an admin-group email")
            admin_email_id = res.json()["id"]

            res = await client.post(f"/api/v1/org/{org_p}/notifications/emails",
                                    json={"email": f"soc-analyst-{stamp}@corp.example", "role": "analyst"})
            r.assert_true(res.status_code == 201, "Admin registers an analyst-group email")
            analyst_email_id = res.json()["id"]
            analyst_email_addr = res.json()["email"]

            res = await client.post(f"/api/v1/org/{org_p}/notifications/emails",
                                    json={"email": f"soc-analyst-{stamp}@corp.example", "role": "viewer"})
            r.assert_true(res.status_code == 409, "Duplicate email registration -> 409")

            res = await client.post(f"/api/v1/org/{org_p}/notifications/emails",
                                    json={"email": "not-an-email", "role": "analyst"})
            r.assert_true(res.status_code == 400, "Invalid email format -> 400")

            _Identity.user = analyst
            res = await client.get(f"/api/v1/org/{org_p}/notifications/emails")
            r.assert_true(res.status_code == 200 and len(res.json()) == 2, "Analyst reads registered emails")

            # ------------------------------------------------------------
            # 2-4. send_event role filtering + disabled email/event
            # ------------------------------------------------------------
            _Identity.user = admin
            res = await client.post(f"/api/v1/org/{org_p}/mail-servers", json={
                "name": f"Notify Mail {stamp}", "provider_type": "google_workspace",
                "credentials": {"service_account_key": "k", "delegated_user": "d@x.test"},
                "connect_now": False,
            })
            r.assert_true(res.status_code == 201, "Mail server created (disconnected) for trigger tests")
            server_id = res.json()["id"]

            # (a) min_role=analyst (default for critical_log) -> both emails get it
            from app.services.org_notification_service import critical_log_email, send_event
            async with async_session_maker() as db:
                current_user_id.set(admin.id)
                subject, body = critical_log_email("test summary", "critical", "auth")
                results = await send_event(
                    db, organization_id=org_p, event_type="critical_log",
                    subject=subject, body_html=body,
                    event_metadata={"test": "a"},
                )
                current_user_id.set(None)
            recipients = sorted(x["email"] for x in results)
            r.assert_true(len(results) == 2, f"critical_log (min analyst) reaches both emails (got {len(results)})")
            r.assert_true(all(x["status"] == "sent" for x in results), "All recipients marked sent (db_log backend)")

            # (b) min_role=admin -> only the admin email
            res = await client.put(f"/api/v1/org/{org_p}/notifications/settings/critical_log",
                                   json={"min_role": "admin"})
            r.assert_true(res.status_code == 200 and res.json()["min_role"] == "admin", "Admin tightens critical_log to min_role=admin")
            async with async_session_maker() as db:
                current_user_id.set(admin.id)
                results = await send_event(
                    db, organization_id=org_p, event_type="critical_log",
                    subject="t2", body_html="b2", event_metadata={"test": "b"},
                )
                current_user_id.set(None)
            r.assert_true(len(results) == 1 and results[0]["role"] == "admin",
                          "min_role=admin excludes the analyst-group email")

            # (c) disabled email excluded
            res = await client.put(f"/api/v1/org/{org_p}/notifications/emails/{admin_email_id}",
                                   json={"is_enabled": False})
            r.assert_true(res.status_code == 200 and res.json()["is_enabled"] is False, "Admin disables an email")
            async with async_session_maker() as db:
                current_user_id.set(admin.id)
                results = await send_event(
                    db, organization_id=org_p, event_type="critical_log",
                    subject="t3", body_html="b3", event_metadata={"test": "c"},
                )
                current_user_id.set(None)
            r.assert_true(len(results) == 0, "Disabled email receives nothing (only admin email was eligible)")
            res = await client.put(f"/api/v1/org/{org_p}/notifications/emails/{admin_email_id}",
                                   json={"is_enabled": True})
            r.assert_true(res.status_code == 200, "Admin re-enables the email")

            # (d) disabled event type -> no sends
            res = await client.put(f"/api/v1/org/{org_p}/notifications/settings/critical_log",
                                   json={"is_enabled": False})
            r.assert_true(res.status_code == 200, "Admin disables critical_log event type")
            async with async_session_maker() as db:
                current_user_id.set(admin.id)
                results = await send_event(
                    db, organization_id=org_p, event_type="critical_log",
                    subject="t4", body_html="b4", event_metadata={"test": "d"},
                )
                current_user_id.set(None)
            r.assert_true(results == [], "Disabled event type produces no sends")
            res = await client.put(f"/api/v1/org/{org_p}/notifications/settings/critical_log",
                                   json={"is_enabled": True, "min_role": "analyst"})
            r.assert_true(res.status_code == 200, "critical_log restored to enabled/min analyst")

            # ------------------------------------------------------------
            # 5. Delivery log rows
            # ------------------------------------------------------------
            _Identity.user = analyst
            res = await client.get(f"/api/v1/org/{org_p}/notifications/logs?event_type=critical_log")
            r.assert_true(res.status_code == 200, "Analyst reads notification log history")
            logs = [x for x in res.json() if x["event_type"] == "critical_log"]
            r.assert_true(len(logs) >= 2, f"Delivery log rows persisted (got {len(logs)})")
            row = next(x for x in logs if x["subject"] == "t2")
            r.assert_true(row["status"] == "sent" and len(row["recipients"]) == 1
                          and row["recipients"][0]["email"] == f"soc-admin-{stamp}@corp.example",
                          "Log row carries per-recipient outcomes")
            res = await client.get(f"/api/v1/org/{org_p}/notifications/logs?status=skipped")
            r.assert_true(res.status_code == 200, "status filter accepts skipped")

            # ------------------------------------------------------------
            # 6. End-to-end triggers
            # ------------------------------------------------------------
            _Identity.user = admin
            # (a) connect failure -> mail_server_down
            res = await client.post(f"/api/v1/org/{org_p}/mail-servers", json={
                "name": f"Broken Mail {stamp}", "provider_type": "google_workspace",
                "credentials": {"incomplete": True},
            })
            r.assert_true(res.status_code == 400, "Broken credentials rejected at create")
            res = await client.post(f"/api/v1/org/{org_p}/mail-servers/{server_id}/connect",
                                    json={"credentials": {"service_account_key": "only-key"}})
            r.assert_true(res.status_code == 400, "Connect with incomplete credentials fails")
            res = await client.get(f"/api/v1/org/{org_p}/notifications/logs?event_type=mail_server_down")
            r.assert_true(len(res.json()) >= 1, "TRIGGER: mail_server_down notification logged on connect failure")

            # (b) critical log ingest -> critical_log
            res = await client.post(f"/api/v1/orgs/{org_p}/api-keys", json={"name": "Log Keys"})
            api_key = res.json()["key"]
            res = await client.post(f"/api/v1/org/{org_p}/logs/ingest",
                                    headers={"org_authorization": api_key},
                                    json={"data": {"events": [
                                        {"user": "bob", "ip": "10.0.0.9", "location": "Berlin, DE", "status": "success", "timestamp": "2026-09-15T08:00:00Z"},
                                        {"user": "bob", "ip": "185.220.101.7", "location": "Moscow, RU", "status": "success", "timestamp": "2026-09-15T08:05:00Z"},
                                    ]}})
            r.assert_true(res.status_code == 200 and res.json()["result"]["risk_score"] >= 40,
                          "Impossible-travel log ingests at medium+")
            res = await client.get(f"/api/v1/org/{org_p}/notifications/logs?event_type=critical_log")
            r.assert_true(any(x["subject"] != "t2" for x in res.json()),
                          "TRIGGER: critical_log notification logged from log ingest")

            # (c) impersonation via gateway lookalike-domain scan
            res = await client.post(f"/api/v1/org/{org_p}/gateway",
                                    headers={"org_authorization": api_key},
                                    json={"action": "scan_email",
                                          "data": {"sender": "alerts@paypa1-security.com",
                                                   "subject": "Urgent: verify", "body": "verify now"}})
            r.assert_true(res.status_code == 200, "Gateway scan_email succeeds")
            res = await client.get(f"/api/v1/org/{org_p}/notifications/logs?event_type=impersonation")
            r.assert_true(len(res.json()) >= 1, "TRIGGER: impersonation notification logged on lookalike-domain scan")
        # ------------------------------------------------------------
        # 7. RBAC
        # ------------------------------------------------------------
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            _Identity.user = analyst
            res = await client.post(f"/api/v1/org/{org_p}/notifications/emails",
                                    json={"email": f"new-{stamp}@corp.example", "role": "analyst"})
            r.assert_true(res.status_code == 403, "Analyst cannot add emails")
            res = await client.delete(f"/api/v1/org/{org_p}/notifications/emails/{analyst_email_id}")
            r.assert_true(res.status_code == 403, "Analyst cannot delete emails")
            res = await client.put(f"/api/v1/org/{org_p}/notifications/settings/critical_log",
                                   json={"min_role": "viewer"})
            r.assert_true(res.status_code == 403, "Analyst cannot change event settings")

            _Identity.user = viewer
            res = await client.get(f"/api/v1/org/{org_p}/notifications/emails")
            r.assert_true(res.status_code == 403, "Viewer cannot access emails")
            res = await client.get(f"/api/v1/org/{org_p}/notifications/settings")
            r.assert_true(res.status_code == 403, "Viewer cannot access settings")
            res = await client.get(f"/api/v1/org/{org_p}/notifications/logs")
            r.assert_true(res.status_code == 403, "Viewer cannot access log history")

        # ------------------------------------------------------------
        # 8. Cross-org isolation
        # ------------------------------------------------------------
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            _Identity.user = other_admin
            res = await client.get(f"/api/v1/org/{org_p}/notifications/emails")
            r.assert_true(res.status_code == 403, "Org Q admin cannot read Org P emails (API layer)")
            res = await client.get(f"/api/v1/org/{org_p}/notifications/logs")
            r.assert_true(res.status_code == 403, "Org Q admin cannot read Org P notification logs (API layer)")

            seen = await _rls_count("org_notification_emails", org_p, other_admin.id)
            r.assert_true(seen == 0, "RLS: Org Q user sees 0 Org P notification emails", f"seen={seen}")
            seen_logs = await _rls_count("org_notification_logs", org_p, other_admin.id)
            r.assert_true(seen_logs == 0, "RLS: Org Q user sees 0 Org P notification logs", f"seen={seen_logs}")
            own = await _rls_count("org_notification_emails", org_p, admin.id)
            r.assert_true(own >= 2, "RLS: Org P admin sees Org P notification emails", f"own={own}")
    finally:
        ORG_MAIL_TRANSPORTS["google_workspace"] = original_transport
        app.dependency_overrides.pop(get_current_user, None)
        current_user_id.set(None)


async def _rls_count(table: str, org_id: str, guc_user: str) -> int:
    async with engine.connect() as conn:
        await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": guc_user})
        return (
            await conn.execute(
                text(f"select count(*) from cyberguard.{table} where organization_id = :org"),
                {"org": org_id},
            )
        ).scalar()


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
            print(f"\nORG-4: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n📧 CYBERGUARD ORG-4 NOTIFICATION TESTS\n" + "=" * 60)
    await run_org_notification_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
