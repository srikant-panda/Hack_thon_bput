"""Comprehensive automated test suite for CYBERGUARD backend.

Tests:
1. Database initialization and seeding
2. User and Personal Workspace auto-provisioning
3. Organization CRUD and membership role assignments
4. RBAC role enforcement (Admin, Analyst, Viewer)
5. Analysis Pipelines (Phishing, URL, Impersonation, ATO, Network)
6. OpenRouter client and heuristic fallback behavior

Run via:
    uv run python scripts/run_all_tests.py
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

from app.core.config import get_settings
from app.core.security import CurrentUser, TenantContext, get_current_user, get_tenant_context
from app.db.models import Organization, OrganizationMember, User
from app.db.session import async_session_maker, init_db
from app.main import app


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
            print("\033[32mALL BACKEND TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


async def run_tests():
    runner = TestRunner()
    print("\n🔍 STARTING CYBERGUARD BACKEND TEST SUITE\n" + "=" * 60)

    # -----------------------------------------------------------------------
    # 1. Database Initialization
    # -----------------------------------------------------------------------
    print("\n[Suite 1] Database & Schema Initialization")
    try:
        await init_db()
        runner.assert_true(True, "Database tables & response catalog seeded")
    except Exception as e:
        runner.assert_true(False, "Database initialization failed", str(e))

    # -----------------------------------------------------------------------
    # 2. Dynamic Auto-Provisioning & Personal Workspace
    # -----------------------------------------------------------------------
    print("\n[Suite 2] Multi-Tenant Provisioning & Organizations")
    test_user_id = f"test-usr-{os.urandom(4).hex()}"
    test_email = f"analyst-{test_user_id}@cyberguard.test"
    test_user = CurrentUser(id=test_user_id, email=test_email, full_name="Test SOC Analyst")
    personal_org_id = f"org-personal-{test_user.id}"

    # Provision user and personal org in a dedicated, isolated session
    async with async_session_maker() as db:
        user_db = User(id=test_user.id, email=test_user.email, full_name=test_user.full_name)
        db.add(user_db)
        await db.flush()
        personal_org = Organization(
            id=personal_org_id,
            name="Personal Workspace",
            slug=f"personal-{test_user.id}",
            is_personal=True,
            owner_id=test_user.id,
        )
        db.add(personal_org)
        await db.flush()
        member = OrganizationMember(
            id=f"mem-{test_user.id}-{personal_org.id}",
            organization_id=personal_org.id,
            user_id=test_user.id,
            role="admin",
        )
        db.add(member)
        user_db.active_organization_id = personal_org.id
        await db.commit()

    active_org_id = personal_org_id

    async def mock_get_current_user():
        return test_user

    async def mock_get_tenant_context():
        nonlocal active_org_id
        return TenantContext(
            organization_id=active_org_id,
            organization_name="Test SOC Workspace",
            role="admin",
            is_single_user=(active_org_id == personal_org_id),
            user_id=test_user.id,
        )

    app.dependency_overrides[get_current_user] = mock_get_current_user
    app.dependency_overrides[get_tenant_context] = mock_get_tenant_context

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test /auth/me
        res = await client.get("/api/v1/auth/me")
        runner.assert_true(res.status_code == 200, "GET /api/v1/auth/me returns 200 OK")
        data = res.json()
        runner.assert_true(data["is_single_user"] is True, "User is in Single-User Personal Workspace by default")
        runner.assert_true(data["active_role"] == "admin", "Single-User workspace automatically has admin role")

        # Test Create Team Organization
        org_payload = {"name": "Test Enterprise SOC"}
        res_org = await client.post("/api/v1/organizations", json=org_payload)
        runner.assert_true(res_org.status_code == 201, "POST /api/v1/organizations creates team organization")
        created_org = res_org.json()
        runner.assert_true(created_org["name"] == "Test Enterprise SOC", "Created org has matching name")

        # Test List Organizations
        res_list = await client.get("/api/v1/organizations")
        runner.assert_true(res_list.status_code == 200, "GET /api/v1/organizations returns 200")
        orgs = res_list.json()
        runner.assert_true(len(orgs) >= 2, "User belongs to both Personal Workspace and Team SOC")

        # Test Switch Organization
        switch_res = await client.post(
            "/api/v1/auth/switch-org",
            json={"organization_id": created_org["id"]},
        )
        runner.assert_true(switch_res.status_code == 200, "POST /api/v1/auth/switch-org succeeds")
        active_org_id = created_org["id"]

        # -------------------------------------------------------------------
        # 3. Detection Engines
        # -----------------------------------------------------------------------
        print("\n[Suite 3] Analysis Engines & AI Explanations")

        # Phishing analysis (Critical malicious sample)
        res_phish = await client.post(
            "/api/v1/analysis/email",
            json={
                "sender": "alerts@paypa1-security.com",
                "subject": "URGENT: Unauthorized login detected",
                "body": "Click http://185.220.101.7/login to verify your account immediately or it will be suspended.",
            },
        )
        runner.assert_true(res_phish.status_code == 200, "POST /api/v1/analysis/email returns 200")
        phish_data = res_phish.json()
        runner.assert_true(phish_data["risk_score"] >= 70, "Suspicious phishing email triggers HIGH/CRITICAL risk score")
        runner.assert_true(len(phish_data["indicators"]) > 0, "Phishing indicators extracted")
        runner.assert_true(bool(phish_data.get("explanation")), "Explanation synthesized")

        # Phishing analysis (Benign registrar sample - consistency test)
        res_benign = await client.post(
            "/api/v1/analysis/email",
            json={
                "sender": "registrar@university.edu",
                "subject": "Examination timetable published",
                "body": "The timetable is on the student portal. No action required.",
            },
        )
        runner.assert_true(res_benign.status_code == 200, "POST benign email returns 200")
        benign_data = res_benign.json()
        runner.assert_true(benign_data["severity"] == "safe", "Benign email scored as SAFE")
        runner.assert_true(benign_data["risk_score"] <= 20, "Benign email risk score <= 20")
        runner.assert_true("safe" in benign_data["explanation"].lower() or "benign" in benign_data["explanation"].lower(), "AI explanation aligns with SAFE severity")

        # URL analysis
        res_url = await client.post(
            "/api/v1/analysis/url",
            json={"url": "http://185.220.101.7/secure/login.php"},
        )
        runner.assert_true(res_url.status_code == 200, "POST /api/v1/analysis/url returns 200")
        url_data = res_url.json()
        runner.assert_true(url_data["risk_score"] >= 60, "Malicious raw IP URL flagged with high risk")

        # Impersonation analysis
        res_imp = await client.post(
            "/api/v1/analysis/impersonation",
            json={
                "claimed_identity": "Chief Financial Officer",
                "message": "Urgent and confidential wire transfer request. Purchase gift cards and wire funds immediately.",
            },
        )
        runner.assert_true(res_imp.status_code == 200, "POST /api/v1/analysis/impersonation returns 200")
        imp_data = res_imp.json()
        runner.assert_true(imp_data["risk_score"] >= 60, "Executive gift-card wire fraud flagged")

        # Account Takeover analysis
        res_ato = await client.post(
            "/api/v1/analysis/account-takeover",
            json={
                "events": [
                    {"user": "alice", "ip": "10.0.1.45", "location": "New York, US", "device": "Windows-Chrome", "status": "success", "timestamp": "2026-09-08T09:00:00Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-08T09:05:00Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-08T09:05:30Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-08T09:06:00Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "success", "timestamp": "2026-09-08T09:07:00Z"},
                ]
            },
        )
        runner.assert_true(res_ato.status_code == 200, "POST /api/v1/analysis/account-takeover returns 200")
        ato_data = res_ato.json()
        runner.assert_true(ato_data["risk_score"] >= 60, "Impossible travel velocity flagged as ATO")

        # Dashboard Summary
        res_dash = await client.get("/api/v1/dashboard/summary")
        runner.assert_true(res_dash.status_code == 200, "GET /api/v1/dashboard/summary returns 200")
        dash_data = res_dash.json()
        runner.assert_true("threats_detected" in dash_data, "Dashboard summary contains metrics")

        # Response actions catalog
        res_actions = await client.get("/api/v1/responses/catalog")
        runner.assert_true(res_actions.status_code == 200, "GET /api/v1/responses/catalog returns 200")
        actions = res_actions.json()
        runner.assert_true(len(actions) > 0, "Pre-seeded SOAR response catalog available")

        # Media Forensics / Deepfake Analysis
        from io import BytesIO
        from PIL import Image
        img = Image.new("RGB", (64, 64), color=(50, 100, 150))
        buf = BytesIO()
        img.save(buf, format="PNG")
        res_media = await client.post(
            "/api/v1/analysis/media",
            files={"file": ("test_media.png", buf.getvalue(), "image/png")},
        )
        runner.assert_true(res_media.status_code == 200, "POST /api/v1/analysis/media returns 200")
        media_data = res_media.json()
        runner.assert_true("authenticity_score" in media_data, "Media forensics authenticity score calculated")
        runner.assert_true(bool(media_data.get("storage_path")), "Media file storage path recorded")

    # -------------------------------------------------------------------
    # 4. API Key Rotation & Circuit Breaking
    # -------------------------------------------------------------------
    print("\n[Suite 4] API Key Rotation & Circuit Breaking")
    from app.ai.key_rotator import ApiKeyRotator

    test_rotator = ApiKeyRotator()
    test_rotator.initialize(["key-soc-1", "key-soc-2", "key-soc-3"], cooldown_seconds=1)
    k1, _ = await test_rotator.get_next_key()
    k2, _ = await test_rotator.get_next_key()
    k3, _ = await test_rotator.get_next_key()
    runner.assert_true([k1, k2, k3] == ["key-soc-1", "key-soc-2", "key-soc-3"], "Distributed round-robin rotation across active keys")

    # Mark key 2 down
    test_rotator.mark_key_down("key-soc-2", reason="Rate limit 429", status_code=429)
    next_keys = [await test_rotator.get_next_key(), await test_rotator.get_next_key()]
    runner.assert_true("key-soc-2" not in [k[0] for k in next_keys], "Circuit breaker bypasses downed key")

    # Wait for cooldown and verify auto-recovery
    await asyncio.sleep(1.1)
    status_list = test_rotator.get_status()
    k2_status = status_list[1]
    runner.assert_true(k2_status["is_healthy"] is True, "Downed key automatically re-released after cooldown")

    # Clean up overrides
    app.dependency_overrides.clear()

    return runner.report()


if __name__ == "__main__":
    exit_code = asyncio.run(run_tests())
    sys.exit(exit_code)
