"""Phase 2 tests — Server-Mode Integration Endpoints (action executor + /integrations/*).

Run standalone:
    uv run python scripts/test_phase2.py

Also imported by scripts/run_all_tests.py as [Suite 6].
"""

import asyncio
import os
import sys
from pathlib import Path

# Ensure backend root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.security import CurrentUser, TenantContext, get_current_user, get_tenant_context
from app.db.models import ActionExecution, Organization, OrganizationMember, User
from app.db.session import async_session_maker, current_user_id, init_db
from app.main import app


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
            print("\033[32mALL PHASE 2 TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


# Payloads calibrated against the real detectors (see Suite 3 thresholds):
PHISHING_EMAIL = {
    "sender": "alerts@paypa1-security.com",
    "recipient": "alice@corp.test",
    "subject": "URGENT: Unauthorized login detected",
    "body": "Click http://185.220.101.7/login to verify your account immediately or it will be suspended.",
    "email_id": "ext-eml-001",
}
BENIGN_EMAIL = {
    "sender": "registrar@university.edu",
    "recipient": "alice@corp.test",
    "subject": "Examination timetable published",
    "body": "The timetable is on the student portal. No action required.",
}
URL_HIGH = "http://185.220.101.7/secure/login.php"  # hybrid ~86 -> high band
URL_MEDIUM = "http://secure-login.paypa1.verify-account.tk/session/renew"  # hybrid ~64 -> medium band
ATO_HISTORY = [
    {"user": "bob", "ip": "10.0.1.45", "location": "New York, US", "device": "Windows-Chrome", "status": "success", "timestamp": "2026-09-11T09:00:00Z"},
    {"user": "bob", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-11T09:02:00Z"},
    {"user": "bob", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-11T09:02:20Z"},
    {"user": "bob", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-11T09:02:40Z"},
    {"user": "bob", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-11T09:03:00Z"},
    {"user": "bob", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-11T09:03:20Z"},
    {"user": "bob", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "success", "timestamp": "2026-09-11T09:04:00Z"},
]


async def run_phase2_tests(runner: TestRunner) -> None:
    """Execute all Phase 2 assertions against the provided runner."""

    await init_db()

    # Provision an isolated org (the seed hook creates its enforcement policy)
    suffix = os.urandom(4).hex()
    user_id = f"usr-p2-{suffix}"
    org_id = f"org-p2-{suffix}"
    test_user = CurrentUser(id=user_id, email=f"p2-{suffix}@cyberguard.test", full_name="Phase Two Analyst")

    current_user_id.set(user_id)  # RLS identity for direct-session provisioning
    async with async_session_maker() as db:
        db.add(User(id=user_id, email=test_user.email, full_name=test_user.full_name))
        await db.flush()
        db.add(Organization(
            id=org_id, name="Phase Two Integration Org", slug=f"p2-{suffix}",
            is_personal=False, owner_id=user_id,
        ))
        await db.flush()
        db.add(OrganizationMember(id=f"mem-p2-{suffix}", organization_id=org_id, user_id=user_id, role="admin"))
        # Mirror the org-creation hook (test bypasses POST /organizations)
        from app.db.models import EnforcementPolicy

        db.add(EnforcementPolicy(
            organization_id=org_id,
            name="Balanced (default)",
            description="Auto-block critical/high, require approval for medium.",
            is_active=True,
        ))
        await db.commit()

    async def mock_get_current_user():
        current_user_id.set(user_id)  # RLS identity, as in production
        return test_user

    async def mock_get_tenant_context():
        return TenantContext(
            organization_id=org_id,
            organization_name="Phase Two Integration Org",
            role="admin",
            is_single_user=False,
            user_id=user_id,
            owner_user_id=user_id,  # rows must satisfy owner-scoped RLS
        )

    app.dependency_overrides[get_current_user] = mock_get_current_user
    app.dependency_overrides[get_tenant_context] = mock_get_tenant_context

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            # -----------------------------------------------------------------
            # 1. Email gateway — critical/high risk, auto-execute
            # -----------------------------------------------------------------
            print("\n[Phase 2.1] Email Gateway Integration (auto-execute)")
            res = await client.post("/api/v1/integrations/email-gateway/analyze",
                                    json={**PHISHING_EMAIL, "mode": "server", "auto_execute": True})
            runner.assert_true(res.status_code == 200, "POST /integrations/email-gateway/analyze returns 200",
                               f"status={res.status_code} body={res.text[:300]}")
            data = res.json()
            runner.assert_true(data["decision"] == "QUARANTINE_EMAIL", "High-risk email -> decision QUARANTINE_EMAIL",
                               f"decision={data['decision']} score={data['risk_score']}")
            runner.assert_true(data["risk_score"] >= 75, "Phishing email risk score in high/critical band",
                               f"score={data['risk_score']}")
            runner.assert_true(data["action_executed"] is True and data["execution_status"] == "success",
                               "Action auto-executed successfully")
            runner.assert_true(bool(data["quarantine_id"]), "Quarantine ID returned to the gateway")
            runner.assert_true(bool(data["explanation"]) and data["mitre_techniques"],
                               "XAI explanation and MITRE mapping included")
            runner.assert_true(bool(data["execution_id"]) and bool(data["policy_id"]),
                               "Execution and policy IDs returned for audit reference")

            execution_id = data["execution_id"]
            alert_id = data["alert_id"]
            async with async_session_maker() as db:
                row = (await db.execute(
                    select(ActionExecution).where(ActionExecution.id == execution_id)
                )).scalar_one_or_none()
                runner.assert_true(row is not None, "ActionExecution record persisted for gateway decision")
                if row is not None:
                    runner.assert_true(
                        row.action_type == "quarantine_email" and row.status == "success",
                        "Persisted execution has correct action_type and status",
                    )
                    runner.assert_true(
                        row.module == "phishing" and row.risk_score == data["risk_score"],
                        "Persisted execution carries denormalized risk context",
                    )
                    runner.assert_true(
                        row.target.get("recipient") == "alice@corp.test",
                        "Execution target extracted from raw_data (recipient)",
                    )

            # -----------------------------------------------------------------
            # 2. URL proxy — medium risk, requires approval
            # -----------------------------------------------------------------
            print("\n[Phase 2.2] URL Proxy Integration (medium -> approval)")
            res = await client.post("/api/v1/integrations/url-proxy/analyze",
                                    json={"url": URL_MEDIUM, "mode": "server", "auto_execute": True})
            runner.assert_true(res.status_code == 200, "POST /integrations/url-proxy/analyze (medium) returns 200",
                               f"status={res.status_code}")
            data = res.json()
            runner.assert_true(40 <= data["risk_score"] < 75, "URL risk score lands in medium band",
                               f"score={data['risk_score']}")
            runner.assert_true(data["decision"] == "TAG_AND_WARN", "Medium-risk URL -> decision TAG_AND_WARN",
                               f"decision={data['decision']}")
            runner.assert_true(data["action_executed"] is False and data["execution_status"] == "pending",
                               "Medium band is not auto-executed (policy default)")
            runner.assert_true(data["requires_approval"] is True and data["approval_url"] == f"/alerts/{data['alert_id']}",
                               "Approval workflow flagged with dashboard URL")

            # -----------------------------------------------------------------
            # 3. URL proxy — high risk, auto-execute block
            # -----------------------------------------------------------------
            print("\n[Phase 2.3] URL Proxy Integration (high -> block)")
            res = await client.post("/api/v1/integrations/url-proxy/analyze",
                                    json={"url": URL_HIGH, "mode": "server", "auto_execute": True})
            runner.assert_true(res.status_code == 200, "POST /integrations/url-proxy/analyze (high) returns 200",
                               f"status={res.status_code}")
            data = res.json()
            runner.assert_true(data["decision"] == "BLOCK_URL", "High-risk URL -> decision BLOCK_URL",
                               f"decision={data['decision']} score={data['risk_score']}")
            runner.assert_true(data["action_executed"] is True and bool(data["block_id"]),
                               "URL blocked with block_id returned")

            # -----------------------------------------------------------------
            # 4. Network flow — benign traffic allowed
            # -----------------------------------------------------------------
            print("\n[Phase 2.4] Network Integration (benign -> allow)")
            res = await client.post("/api/v1/integrations/network/analyze-flow",
                                    json={
                                        "source_ip": "10.0.0.2", "destination_ip": "142.250.183.14",
                                        "port": 443, "protocol": "tcp", "bytes_transferred": 2048,
                                        "mode": "server", "auto_execute": True,
                                    })
            runner.assert_true(res.status_code == 200, "POST /integrations/network/analyze-flow returns 200",
                               f"status={res.status_code}")
            data = res.json()
            runner.assert_true(data["decision"] == "ALLOW", "Benign flow -> decision ALLOW",
                               f"decision={data['decision']} score={data['risk_score']}")
            runner.assert_true(data["action_executed"] is True, "ALLOW decision recorded as executed no-op")

            # -----------------------------------------------------------------
            # 5. Auth/SSO — impossible travel + burst -> revoke session
            # -----------------------------------------------------------------
            print("\n[Phase 2.5] Auth/SSO Integration (ATO -> revoke session)")
            res = await client.post("/api/v1/integrations/auth/analyze-login",
                                    json={
                                        "user_id": "bob", "source_ip": "185.220.101.7",
                                        "location": "Moscow, RU", "device_fingerprint": "Linux-Firefox",
                                        "timestamp": "2026-09-11T09:04:00Z",
                                        "recent_events": ATO_HISTORY,
                                        "mode": "server", "auto_execute": True,
                                    })
            runner.assert_true(res.status_code == 200, "POST /integrations/auth/analyze-login returns 200",
                               f"status={res.status_code} body={res.text[:300]}")
            data = res.json()
            runner.assert_true(data["risk_score"] >= 60, "ATO risk score in high band (>=60)",
                               f"score={data['risk_score']}")
            runner.assert_true(data["decision"] == "REVOKE_SESSION", "ATO verdict -> decision REVOKE_SESSION",
                               f"decision={data['decision']}")
            runner.assert_true(data["action_executed"] is True and data["execution_status"] == "success",
                               "Session revocation auto-executed")

            # -----------------------------------------------------------------
            # 6. Media moderation — upstream confidence passthrough
            # -----------------------------------------------------------------
            print("\n[Phase 2.6] Media Moderation Integration")
            res = await client.post("/api/v1/integrations/media/analyze",
                                    json={
                                        "media_type": "image", "media_id": "med-001",
                                        "metadata": {"manipulation_confidence": 0.92},
                                        "mode": "server", "auto_execute": True,
                                    })
            runner.assert_true(res.status_code == 200, "POST /integrations/media/analyze (high confidence) returns 200",
                               f"status={res.status_code}")
            data = res.json()
            runner.assert_true(data["risk_score"] >= 85, "Upstream manipulation confidence passed through as score",
                               f"score={data['risk_score']}")
            runner.assert_true(data["decision"] == "FLAG_FOR_REVIEW" and data["action_executed"] is True,
                               "High-confidence manipulation -> flagged for review (executed)",
                               f"decision={data['decision']}")

            res = await client.post("/api/v1/integrations/media/analyze",
                                    json={"media_type": "image", "media_id": "med-002",
                                          "metadata": {}, "mode": "server", "auto_execute": True})
            data = res.json()
            runner.assert_true(data["decision"] == "ALLOW" and data["risk_score"] <= 20,
                               "Clean media metadata -> ALLOW", f"decision={data['decision']} score={data['risk_score']}")

            # -----------------------------------------------------------------
            # 7. Client mode never enforces
            # -----------------------------------------------------------------
            print("\n[Phase 2.7] Client Mode Through Integration Surface")
            res = await client.post("/api/v1/integrations/email-gateway/analyze",
                                    json={**PHISHING_EMAIL, "mode": "client", "auto_execute": True})
            runner.assert_true(res.status_code == 200, "Client-mode integration request returns 200")
            data = res.json()
            runner.assert_true(data["action_executed"] is False and data["execution_status"] == "skipped",
                               "Client mode records recommendation only (skipped)")
            runner.assert_true(data["requires_approval"] is False, "Client mode has no approval workflow")

            # Benign email sanity — server mode, no indicators -> allow
            res = await client.post("/api/v1/integrations/email-gateway/analyze",
                                    json={**BENIGN_EMAIL, "mode": "server", "auto_execute": True})
            data = res.json()
            runner.assert_true(data["decision"] == "ALLOW" and data["risk_score"] <= 20,
                               "Benign email -> ALLOW (no false-positive enforcement)",
                               f"decision={data['decision']} score={data['risk_score']}")

            # -----------------------------------------------------------------
            # 8. Authentication is enforced on integration surface
            # -----------------------------------------------------------------
            print("\n[Phase 2.8] Integration Auth Enforcement")
            saved_user = app.dependency_overrides.pop(get_current_user)
            saved_tenant = app.dependency_overrides.pop(get_tenant_context, None)
            try:
                res = await client.post("/api/v1/integrations/email-gateway/analyze", json=PHISHING_EMAIL)
                # Codebase maps missing/invalid tokens to 403 (PermissionDeniedError)
                runner.assert_true(res.status_code == 403, "Integration endpoint rejects unauthenticated callers",
                                   f"status={res.status_code}")
            finally:
                app.dependency_overrides[get_current_user] = saved_user
                if saved_tenant is not None:
                    app.dependency_overrides[get_tenant_context] = saved_tenant
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_tenant_context, None)


async def _standalone() -> int:
    runner = TestRunner()
    print("\n🛡️ STARTING CYBERGUARD PHASE 2 TEST SUITE\n" + "=" * 60)
    await run_phase2_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
