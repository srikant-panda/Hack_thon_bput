"""ORG-2 — Dashboards + Splunk Log Analysis test suite (Suite 18).

Covers:
1.  Dashboard summary counts (org-scoped)
2.  Feature dashboard feeds + filters (module, severity, dates, pagination)
3.  Log ingest: shape auto-detection (auth/network/app), ATO analysis,
    medium+ promotion to the alert plane
4.  Log stream initial load + realtime publication wiring
5.  Manual actions: analyst records block_ip -> manual_action_taken + audit
6.  RBAC: viewer cannot take actions (403), analyst can
7.  Cross-org isolation: API layer (403) and RLS layer (0 rows)

Run via run_all_tests.py (Suite 18) or standalone:
    uv run python scripts/test_org_dashboards.py
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


async def _seed_scan(org_id: str, owner_id: str, module: str, severity: str, score: int) -> None:
    """Insert one Event + Alert directly (service role; org dashboard reads
    run through the service role, matching production aggregation)."""
    from datetime import datetime, timezone

    from app.db.admin import _get_admin_session_maker
    from app.db.models import Alert, Event

    async with _get_admin_session_maker()() as db:
        event_id = str(uuid.uuid4())
        db.add(Event(
            id=event_id, organization_id=org_id, owner_user_id=owner_id,
            event_type=module, source="test", raw_data={}, status="completed",
        ))
        db.add(Alert(
            id=str(uuid.uuid4()), organization_id=org_id, owner_user_id=owner_id,
            event_id=event_id, title=f"{module} {severity} test scan",
            module=module, threat_type=module, severity=severity, risk_score=score,
            status="new", summary="seeded scan", indicators=[],
            explanation="Seeded explanation for verbose dashboard test",
            created_at=datetime.now(timezone.utc),
        ))
        await db.commit()


async def run_org_dashboard_tests(runner) -> None:
    r = _runner_shim(runner)
    print("\n" + "-" * 60)
    print("ORG-2 Dashboards: summary, feature feeds, log analysis, RBAC")
    print("-" * 60)

    stamp = uuid.uuid4().hex[:8]
    admin = CurrentUser(id=f"orgd-admin-{stamp}", email=f"orgd-admin-{stamp}@cyberguard.test", full_name="Org D Admin")
    analyst = CurrentUser(id=f"orgd-analyst-{stamp}", email=f"orgd-analyst-{stamp}@cyberguard.test", full_name="Org D Analyst")
    viewer = CurrentUser(id=f"orgd-viewer-{stamp}", email=f"orgd-viewer-{stamp}@cyberguard.test", full_name="Org D Viewer")
    other_admin = CurrentUser(id=f"orge-admin-{stamp}", email=f"orge-admin-{stamp}@cyberguard.test", full_name="Org E Admin")

    async with async_session_maker() as db:
        for u in (admin, analyst, viewer, other_admin):
            await _ensure_user(db, u.id, u.email or "", u.full_name or "")

    app.dependency_overrides[get_current_user] = _mock_get_current_user

    org_d = org_e = ""
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # ------------------------------------------------------------
            # Setup: two orgs, members, 10 seeded scans on Org D
            # ------------------------------------------------------------
            _Identity.user = admin
            org_d = (await client.post("/api/v1/orgs", json={"name": f"Dash Org D {stamp}"})).json()["id"]
            _Identity.user = other_admin
            org_e = (await client.post("/api/v1/orgs", json={"name": f"Dash Org E {stamp}"})).json()["id"]

            _Identity.user = admin
            res_a = await client.post(f"/api/v1/orgs/{org_d}/members", json={"email": analyst.email, "role": "analyst"})
            res_v = await client.post(f"/api/v1/orgs/{org_d}/members", json={"email": viewer.email, "role": "viewer"})
            r.assert_true(res_a.status_code == 201 and res_v.status_code == 201, "Admin adds analyst + viewer members")

            owner_id = admin.id
            for i in range(10):
                module = "phishing" if i < 4 else ("url" if i < 7 else "impersonation")
                severity = "critical" if i % 5 == 0 else "medium"
                await _seed_scan(org_d, owner_id, module, severity, 90 if severity == "critical" else 55)

            # ------------------------------------------------------------
            # 1. Dashboard summary
            # ------------------------------------------------------------
            _Identity.user = admin
            res = await client.get(f"/api/v1/org/{org_d}/dashboard/summary")
            r.assert_true(res.status_code == 200, "GET /dashboard/summary returns 200 (analyst+)")
            s = res.json()
            r.assert_true(s["total_scans"] >= 10, f"total_scans reflects seeded events (got {s['total_scans']})")
            r.assert_true(s["threats_detected"] >= 10, f"threats_detected reflects seeded alerts (got {s['threats_detected']})")
            r.assert_true(s["critical_alerts"] == 2, f"critical_alerts == 2 (got {s['critical_alerts']})")

            # ------------------------------------------------------------
            # 2. Feature dashboard feeds + filters
            # ------------------------------------------------------------
            res = await client.get(f"/api/v1/org/{org_d}/dashboard/phishing")
            r.assert_true(res.status_code == 200, "GET /dashboard/phishing returns 200")
            feed = res.json()
            r.assert_true(feed["total"] == 4, f"phishing feed has exactly the 4 seeded rows (got {feed['total']})")
            r.assert_true(all(row["severity"] in ("critical", "medium") for row in feed["rows"]), "Feed rows carry severity")
            r.assert_true(bool(feed["rows"][0]["explanation"]), "Verbose rows include explanation")

            res = await client.get(f"/api/v1/org/{org_d}/dashboard/url")
            r.assert_true(res.json()["total"] == 3, "url feed returns only url-module scans")

            res = await client.get(f"/api/v1/org/{org_d}/dashboard/phishing?severity=critical")
            r.assert_true(res.json()["total"] == 1, "severity filter narrows the feed")

            res = await client.get(f"/api/v1/org/{org_d}/dashboard/phishing?limit=2&offset=1")
            body = res.json()
            r.assert_true(len(body["rows"]) == 2 and body["total"] == 4, "limit/offset paginate without losing total")

            res = await client.get(f"/api/v1/org/{org_d}/dashboard/phishing?from_date=1999-01-01T00:00:00Z")
            r.assert_true(res.json()["total"] == 4, "from_date in the past keeps all rows")
            res = await client.get(f"/api/v1/org/{org_d}/dashboard/phishing?to_date=1999-01-01T00:00:00Z")
            r.assert_true(res.json()["total"] == 0, "to_date in the past excludes all rows")

            res = await client.get(f"/api/v1/org/{org_d}/dashboard/unknown")
            r.assert_true(res.status_code == 404, "Unknown feature -> 404")

            _Identity.user = viewer
            res = await client.get(f"/api/v1/org/{org_d}/dashboard/summary")
            r.assert_true(res.status_code == 403, "Viewer blocked from analyst+ summary (403)")
            _Identity.user = other_admin
            res = await client.get(f"/api/v1/org/{org_d}/dashboard/summary")
            r.assert_true(res.status_code == 403, "Org E admin cannot read Org D summary (API layer)")

            # ------------------------------------------------------------
            # 3. Log ingest: auto-detection + analysis
            # ------------------------------------------------------------
            _Identity.user = admin
            res_key = await client.post(f"/api/v1/orgs/{org_d}/api-keys", json={"name": "Log Pipe"})
            raw_key = res_key.json()["key"]
            headers = {"org_authorization": raw_key}

            auth_payload = {
                "data": {"events": [
                    {"user": "alice", "ip": "10.0.1.45", "location": "New York, US", "device": "Windows-Chrome", "status": "success", "timestamp": "2026-09-15T09:00:00Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-15T09:05:00Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-15T09:05:30Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "success", "timestamp": "2026-09-15T09:07:00Z"},
                ]}
            }
            res = await client.post(f"/api/v1/org/{org_d}/logs/ingest", headers=headers, json=auth_payload)
            r.assert_true(res.status_code == 200 and res.json()["status"] == "analyzed", "Auth log ingests + analyzes")
            ingest = res.json()
            r.assert_true(ingest["log_type"] == "auth", "Auth shape auto-detected as 'auth'")
            r.assert_true(ingest["result"]["risk_score"] >= 40, f"Impossible-travel auth log scores medium+ (got {ingest['result']['risk_score']})")
            r.assert_true(bool(ingest["result"]["indicators"]), "ATO indicators extracted")
            r.assert_true(bool(ingest.get("alert_id")), "Medium+ log promoted to the alert plane")

            res = await client.post(
                f"/api/v1/org/{org_d}/logs/ingest", headers=headers,
                json={"data": {"src_ip": "185.220.101.7", "dst_ip": "10.0.0.5", "port": 22, "bytes": 99999}},
            )
            r.assert_true(res.json()["log_type"] == "network", "Network shape auto-detected as 'network'")

            res = await client.post(
                f"/api/v1/org/{org_d}/logs/ingest", headers=headers,
                json={"data": {"timestamp": "2026-09-15T10:00:00Z", "level": "error", "message": "Failed password for root from 185.220.101.7 port 4482"}},
            )
            r.assert_true(res.json()["log_type"] == "app", "App shape auto-detected as 'app'")
            app_log = res.json()
            r.assert_true(any(i["type"] == "auth_failure" for i in app_log["result"]["indicators"]), "App-log auth-failure pattern detected")

            res = await client.post(
                f"/api/v1/org/{org_d}/logs/ingest", headers=headers,
                json={"data": {"level": "info", "message": "Scheduled job completed"}},
            )
            r.assert_true(res.json()["result"]["severity"] in ("safe", "low"), "Benign app log scores safe/low")

            res_wrong = await client.post(f"/api/v1/org/{org_e}/logs/ingest", headers=headers, json=auth_payload)
            r.assert_true(res_wrong.status_code == 403, "Org D key against Org E ingest -> 403")

            # ------------------------------------------------------------
            # 4. Log stream (initial load) + realtime publication wiring
            # ------------------------------------------------------------
            _Identity.user = analyst
            res = await client.get(f"/api/v1/org/{org_d}/logs/stream")
            r.assert_true(res.status_code == 200, "GET /logs/stream returns 200 (member)")
            stream = res.json()
            r.assert_true(len(stream) >= 4, f"Stream returns the ingested logs (got {len(stream)})")
            r.assert_true(stream[0]["created_at"] >= stream[-1]["created_at"], "Stream ordered newest-first")
            r.assert_true(bool(stream[0]["analysis_result"]), "Stream rows carry the analysis result")

            res = await client.get(f"/api/v1/org/{org_d}/logs/stream?severity=critical")
            r.assert_true(all(row["severity"] == "critical" for row in res.json()), "severity filter works on stream")

            is_pg = "postgresql" in str(engine.dialect.name)
            if is_pg:
                async with engine.connect() as conn:
                    in_pub = (
                        await conn.execute(text(
                            "select count(*) from pg_publication_tables "
                            "where pubname='supabase_realtime' and schemaname='cyberguard' "
                            "and tablename in ('org_log_events','alerts')"
                        ))
                    ).scalar()
                r.assert_true(in_pub == 2, "org_log_events + alerts are in the supabase_realtime publication")
            else:
                r.assert_true(True, "Realtime publication check skipped without PostgreSQL")

            # ------------------------------------------------------------
            # 5-6. Manual actions + RBAC
            # ------------------------------------------------------------
            target_log = stream[0]["id"]
            res = await client.post(
                f"/api/v1/org/{org_d}/logs/{target_log}/action",
                json={"action": "block_ip", "target": "185.220.101.7", "note": "impossible travel"},
            )
            r.assert_true(res.status_code == 200, "Analyst takes block_ip action")
            action = res.json()
            r.assert_true(action["taken_by"] == analyst.id, "Action recorded against the acting analyst")

            _Identity.user = analyst
            res = await client.get(f"/api/v1/org/{org_d}/logs/stream")
            row = next(x for x in res.json() if x["id"] == target_log)
            r.assert_true(row["manual_action_taken"] == "block_ip" and bool(row["acted_at"]), "manual_action_taken + acted_at persisted")

            async with async_session_maker() as db:
                current_user_id.set(analyst.id)
                from sqlalchemy import select as sa_select
                from app.db.models import AuditLog
                audits = (await db.execute(
                    sa_select(AuditLog).where(AuditLog.action == "org_log:block_ip", AuditLog.resource == f"org_log_events/{target_log}")
                )).scalars().all()
                current_user_id.set(None)
            r.assert_true(len(audits) == 1, "Audit-log entry created for the manual action")

            _Identity.user = viewer
            res = await client.post(
                f"/api/v1/org/{org_d}/logs/{target_log}/action", json={"action": "revoke_session"}
            )
            r.assert_true(res.status_code == 403, "Viewer cannot take manual actions (403)")

            _Identity.user = analyst
            res = await client.post(
                f"/api/v1/org/{org_d}/logs/{target_log}/action", json={"action": "nuke_everything"}
            )
            r.assert_true(res.status_code in (400, 422), "Invalid action value rejected (400/422)")

            # ------------------------------------------------------------
            # 7. Cross-org isolation
            # ------------------------------------------------------------
            _Identity.user = other_admin
            res = await client.get(f"/api/v1/org/{org_d}/logs/stream")
            r.assert_true(res.status_code == 403, "Org E admin cannot read Org D log stream (API layer)")
            res = await client.post(
                f"/api/v1/org/{org_d}/logs/{target_log}/action", json={"action": "mark_safe"}
            )
            r.assert_true(res.status_code == 403, "Org E admin cannot act on Org D logs (API layer)")

            if is_pg:
                seen = await _rls_log_count(org_d, other_admin.id)
                r.assert_true(seen == 0, "RLS: Org E user sees 0 Org D log rows", f"seen={seen}")
                seen_admin = await _rls_log_count(org_d, admin.id)
                r.assert_true(seen_admin >= 4, "RLS: Org D admin sees Org D log rows", f"seen={seen_admin}")
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        current_user_id.set(None)


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


async def _rls_log_count(org_id: str, guc_user: str) -> int:
    async with engine.connect() as conn:
        await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": guc_user})
        return (
            await conn.execute(
                text("select count(*) from cyberguard.org_log_events where organization_id = :org"),
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
            print(f"\nORG-2: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n📊 CYBERGUARD ORG-2 DASHBOARDS TESTS\n" + "=" * 60)
    await run_org_dashboard_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
