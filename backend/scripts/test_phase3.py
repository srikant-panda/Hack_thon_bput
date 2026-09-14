"""Phase 3 tests — Approval Workflow, Quarantine/Block Lists & Policy Management.

Run standalone:
    uv run python scripts/test_phase3.py

Also imported by scripts/run_all_tests.py as [Suite 7].
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Ensure backend root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.security import CurrentUser, TenantContext, get_current_user, get_tenant_context
from app.db.models import (
    ActionExecution,
    Alert,
    AuditLog,
    EnforcementPolicy,
    Organization,
    OrganizationMember,
    User,
)
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
            print("\033[32mALL PHASE 3 TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


async def _make_execution(
    *,
    org_id: str,
    owner_user_id: str = "",
    alert_id: Optional[str],
    action_type: str,
    status: str,
    module: str = "phishing",
    severity: str = "high",
    risk_score: int = 80,
    requires_approval: bool = False,
) -> str:
    """Insert an ActionExecution row directly and return its id."""
    exec_id = str(uuid.uuid4())
    async with async_session_maker() as db:
        db.add(ActionExecution(
            id=exec_id,
            organization_id=org_id,
            owner_user_id=owner_user_id or None,
            alert_id=alert_id,
            action_type=action_type,
            target={"email_id": "eml-x", "recipient": "victim@corp.test", "url": "http://evil.test"},
            status=status,
            execution_mode="server",
            triggered_by="api",
            triggered_by_id="email-gateway-01",
            requires_approval=requires_approval,
            executed_at=datetime.now(timezone.utc) if status == "success" else None,
            execution_result={"simulated": True, "message": "test fixture"} if status == "success" else None,
            risk_score=risk_score,
            severity=severity,
            threat_type=module,
            module=module,
        ))
        await db.commit()
    return exec_id


async def _make_alert(*, org_id: str, owner_user_id: str = "", module: str = "phishing") -> str:
    alert_id = str(uuid.uuid4())
    async with async_session_maker() as db:
        db.add(Alert(
            id=alert_id,
            organization_id=org_id,
            owner_user_id=owner_user_id or None,
            title="Phase Three fixture alert",
            module=module,
            severity="high",
            risk_score=82,
        ))
        await db.commit()
    return alert_id


async def run_phase3_tests(runner: TestRunner) -> None:
    """Execute all Phase 3 assertions against the provided runner."""

    await init_db()

    suffix = os.urandom(4).hex()
    user_id = f"usr-p3-{suffix}"
    org_id = f"org-p3-{suffix}"
    test_user = CurrentUser(id=user_id, email=f"p3-{suffix}@cyberguard.test", full_name="Phase Three Admin")

    current_user_id.set(user_id)  # RLS identity for direct-session provisioning
    async with async_session_maker() as db:
        db.add(User(id=user_id, email=test_user.email, full_name=test_user.full_name))
        await db.flush()
        db.add(Organization(
            id=org_id, name="Phase Three Org", slug=f"p3-{suffix}",
            is_personal=False, owner_id=user_id,
        ))
        await db.flush()
        db.add(OrganizationMember(id=f"mem-p3-{suffix}", organization_id=org_id, user_id=user_id, role="admin"))
        db.add(EnforcementPolicy(
            organization_id=org_id, name="Balanced (default)",
            description="Phase Three default", is_active=True,
        ))
        await db.commit()

    # Fetch the seeded policy id
    async with async_session_maker() as db:
        policy = (await db.execute(
            select(EnforcementPolicy).where(EnforcementPolicy.organization_id == org_id)
        )).scalars().first()
    policy_id = policy.id

    # Mutable role for RBAC scenarios
    current_role = {"value": "admin"}

    async def mock_get_current_user():
        current_user_id.set(user_id)  # RLS identity, as in production
        return test_user

    async def mock_get_tenant_context():
        return TenantContext(
            organization_id=org_id,
            organization_name="Phase Three Org",
            role=current_role["value"],
            is_single_user=False,
            user_id=test_user.id,
            owner_user_id=user_id,  # rows must satisfy owner-scoped RLS
        )

    app.dependency_overrides[get_current_user] = mock_get_current_user
    app.dependency_overrides[get_tenant_context] = mock_get_tenant_context

    # -----------------------------------------------------------------------
    # Fixtures: a mix of executions with different statuses/modules
    # -----------------------------------------------------------------------
    alert_id = await _make_alert(org_id=org_id, owner_user_id=user_id)
    exec_pending = await _make_execution(
        org_id=org_id, owner_user_id=user_id, alert_id=alert_id, action_type="quarantine_email",
        status="pending", requires_approval=True,
    )
    exec_pending_2 = await _make_execution(
        org_id=org_id, owner_user_id=user_id, alert_id=alert_id, action_type="block_url",
        status="pending", module="url", requires_approval=True,
    )
    exec_quarantined = await _make_execution(
        org_id=org_id, owner_user_id=user_id, alert_id=alert_id, action_type="quarantine_email", status="success",
    )
    exec_blocked = await _make_execution(
        org_id=org_id, owner_user_id=user_id, alert_id=alert_id, action_type="block_url", status="success", module="url",
    )
    exec_rejected = await _make_execution(
        org_id=org_id, owner_user_id=user_id, alert_id=alert_id, action_type="rate_limit", status="rejected", module="network",
    )
    exec_skipped = await _make_execution(
        org_id=org_id, owner_user_id=user_id, alert_id=alert_id, action_type="block", status="skipped",
    )
    # A second org's record — must never leak into listings
    # (create the org row first: Postgres enforces the FK, SQLite did not)
    async with async_session_maker() as db:
        db.add(Organization(
            id=f"org-other-{suffix}", name="Other Org", slug=f"other-{suffix}",
            is_personal=False, owner_id=user_id,
        ))
        await db.commit()
    other_exec = await _make_execution(
        org_id=f"org-other-{suffix}", owner_user_id=user_id, alert_id=None,
        action_type="quarantine_email", status="success",
    )

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            # -----------------------------------------------------------------
            # Group 1: Action listing & filtering
            # -----------------------------------------------------------------
            print("\n[Phase 3.1] Action Listing & Filtering")
            res = await client.get("/api/v1/actions")
            runner.assert_true(res.status_code == 200, "GET /api/v1/actions returns 200")
            data = res.json()
            runner.assert_true(data["total"] == 6, "All six org executions listed (other org excluded)",
                               f"total={data['total']}")
            listed_ids = {i["id"] for i in data["items"]}
            runner.assert_true(other_exec not in listed_ids, "Cross-tenant execution never leaks")

            res = await client.get("/api/v1/actions", params={"status": "pending"})
            data = res.json()
            runner.assert_true(
                data["total"] == 2 and all(i["status"] == "pending" for i in data["items"]),
                "status=pending filter returns only pending executions",
            )

            res = await client.get("/api/v1/actions", params={"module": "url"})
            data = res.json()
            runner.assert_true(
                data["total"] == 2 and all(i["module"] == "url" for i in data["items"]),
                "module=url filter returns only URL executions",
            )

            res = await client.get("/api/v1/actions", params={"page": 1, "page_size": 4})
            data = res.json()
            runner.assert_true(
                data["total"] == 6 and len(data["items"]) == 4 and data["page"] == 1,
                "Pagination returns first page of 4 with total preserved",
            )

            res = await client.get(f"/api/v1/actions/{exec_pending}")
            runner.assert_true(
                res.status_code == 200 and res.json()["id"] == exec_pending,
                "GET /api/v1/actions/{id} returns the single execution",
            )
            res = await client.get(f"/api/v1/actions/{uuid.uuid4()}")
            runner.assert_true(res.status_code == 404, "Unknown action id returns 404")

            # -----------------------------------------------------------------
            # Group 2: Approval workflow
            # -----------------------------------------------------------------
            print("\n[Phase 3.2] Approval Workflow")
            res = await client.post(f"/api/v1/actions/{exec_pending}/approve", json={"comment": "Confirmed malicious"})
            runner.assert_true(res.status_code == 200, "POST /actions/{id}/approve returns 200",
                               f"status={res.status_code} body={res.text[:200]}")
            data = res.json()
            runner.assert_true(data["status"] == "success", "Approved action executed (status=success)")
            runner.assert_true(data["approved_by"] == test_user.id and data["approved_at"],
                               "approved_by and approved_at recorded")
            runner.assert_true(
                bool(data["execution_result"]) and data["execution_result"].get("quarantine_id"),
                "Execution result populated on approval (quarantine_id present)",
            )
            res = await client.post(f"/api/v1/actions/{exec_pending}/approve", json={})
            runner.assert_true(res.status_code == 400, "Re-approving a non-pending action returns 400")

            res = await client.post(f"/api/v1/actions/{exec_skipped}/approve", json={})
            runner.assert_true(res.status_code == 400, "Approving a requires_approval=False action returns 400")

            # -----------------------------------------------------------------
            # Group 3: Rejection workflow
            # -----------------------------------------------------------------
            print("\n[Phase 3.3] Rejection Workflow")
            res = await client.post(f"/api/v1/actions/{exec_pending_2}/reject",
                                    json={"reason": "Verified legitimate IT scan"})
            runner.assert_true(res.status_code == 200, "POST /actions/{id}/reject returns 200")
            data = res.json()
            runner.assert_true(data["status"] == "rejected" and data["rejection_reason"] == "Verified legitimate IT scan",
                               "Rejection reason stored")
            runner.assert_true(data["executed_at"] is None and not data["execution_result"],
                               "Rejected action never executed")
            res = await client.post(f"/api/v1/actions/{exec_pending_2}/reject", json={"reason": "again"})
            runner.assert_true(res.status_code == 400, "Re-rejecting a non-pending action returns 400")

            # -----------------------------------------------------------------
            # Group 4: Quarantine management
            # -----------------------------------------------------------------
            print("\n[Phase 3.4] Quarantine Management")
            res = await client.get("/api/v1/actions/quarantine/list")
            data = res.json()
            runner.assert_true(
                res.status_code == 200 and data["total"] == 2
                and {i["id"] for i in data["items"]} == {exec_quarantined, exec_pending},
                "Quarantine queue lists successful quarantine executions "
                "(original + the one approved in Group 2; rejected/skipped excluded)",
                f"total={data['total']}",
            )
            res = await client.post(f"/api/v1/actions/quarantine/{exec_quarantined}/release")
            runner.assert_true(res.status_code == 200, "POST /quarantine/{id}/release returns 200")
            data = res.json()
            runner.assert_true(data["status"] == "released", "Released quarantine has status 'released'")
            runner.assert_true(
                data["execution_result"].get("released_by") == test_user.id
                and bool(data["execution_result"].get("released_at")),
                "Release recorded with released_by and released_at",
            )
            res = await client.post(f"/api/v1/actions/quarantine/{exec_blocked}/release")
            runner.assert_true(res.status_code == 400, "Releasing a non-quarantine action returns 400")

            # -----------------------------------------------------------------
            # Group 5: Block list management
            # -----------------------------------------------------------------
            print("\n[Phase 3.5] Block List Management")
            res = await client.get("/api/v1/actions/blocklist/list")
            data = res.json()
            runner.assert_true(
                res.status_code == 200 and data["total"] == 1 and data["items"][0]["id"] == exec_blocked,
                "Block list shows only successful block executions",
                f"total={data['total']}",
            )
            res = await client.post(f"/api/v1/actions/blocklist/{exec_blocked}/unblock")
            runner.assert_true(res.status_code == 200, "POST /blocklist/{id}/unblock returns 200")
            data = res.json()
            runner.assert_true(data["status"] == "unblocked", "Unblocked item has status 'unblocked'")
            runner.assert_true(bool(data["execution_result"].get("unblocked_by")), "Unblock recorded with unblocked_by")
            res = await client.post(f"/api/v1/actions/blocklist/{exec_rejected}/unblock")
            runner.assert_true(res.status_code == 400, "Unblocking a non-success action returns 400")

            # -----------------------------------------------------------------
            # Group 6: Policy management
            # -----------------------------------------------------------------
            print("\n[Phase 3.6] Policy Management")
            res = await client.get("/api/v1/policies")
            runner.assert_true(res.status_code == 200, "GET /api/v1/policies returns 200")
            data = res.json()
            runner.assert_true(
                len(data["policies"]) == 1 and data["active_policy_id"] == policy_id,
                "Org policy listed with active_policy_id",
            )

            res = await client.get(f"/api/v1/policies/{policy_id}")
            runner.assert_true(res.status_code == 200 and res.json()["phishing_high_threshold"] == 75,
                               "GET /policies/{id} returns policy with default thresholds")

            res = await client.put(f"/api/v1/policies/{policy_id}", json={"phishing_high_threshold": 80})
            runner.assert_true(res.status_code == 200 and res.json()["phishing_high_threshold"] == 80,
                               "PUT /policies/{id} updates threshold")

            res = await client.put(f"/api/v1/policies/{policy_id}", json={"action_on_high": "launch_missiles"})
            runner.assert_true(res.status_code == 400, "Invalid action vocabulary rejected with 400")

            # Create a second policy and activate it
            async with async_session_maker() as db:
                second_policy = EnforcementPolicy(
                    organization_id=org_id, name="Strict", is_active=False,
                )
                db.add(second_policy)
                await db.commit()
                second_policy_id = second_policy.id

            res = await client.post(f"/api/v1/policies/{second_policy_id}/activate")
            runner.assert_true(res.status_code == 200 and res.json()["is_active"] is True,
                               "POST /policies/{id}/activate activates policy")
            res = await client.get("/api/v1/policies")
            data = res.json()
            actives = [p for p in data["policies"] if p["is_active"]]
            runner.assert_true(
                len(actives) == 1 and actives[0]["id"] == second_policy_id and data["active_policy_id"] == second_policy_id,
                "Activating one policy deactivates all others (single active)",
            )

            # -----------------------------------------------------------------
            # Group 7: RBAC enforcement
            # -----------------------------------------------------------------
            print("\n[Phase 3.7] RBAC Enforcement")

            # Viewer: read OK, approve/reject 403
            current_role["value"] = "viewer"
            res = await client.get("/api/v1/actions")
            runner.assert_true(res.status_code == 200, "Viewer can list actions")
            res = await client.get("/api/v1/policies")
            runner.assert_true(res.status_code == 200, "Viewer can read policies")
            res = await client.post(f"/api/v1/actions/{exec_pending}/approve", json={})
            runner.assert_true(res.status_code == 403, "Viewer cannot approve (403)")
            res = await client.put(f"/api/v1/policies/{policy_id}", json={"name": "Hacked"})
            runner.assert_true(res.status_code == 403, "Viewer cannot update policies (403)")

            # Analyst: approve OK, policy mutation 403
            current_role["value"] = "analyst"
            exec_pending_3 = await _make_execution(
                org_id=org_id, owner_user_id=user_id, alert_id=alert_id, action_type="block_url",
                status="pending", module="url", requires_approval=True,
            )
            res = await client.post(f"/api/v1/actions/{exec_pending_3}/approve", json={})
            runner.assert_true(res.status_code == 200, "Analyst can approve pending actions")
            res = await client.put(f"/api/v1/policies/{policy_id}", json={"name": "Analyst Edit"})
            runner.assert_true(res.status_code == 403, "Analyst cannot update policies (403)")
            res = await client.post(f"/api/v1/policies/{policy_id}/activate")
            runner.assert_true(res.status_code == 403, "Analyst cannot activate policies (403)")

            # Admin: everything (already exercised above); re-verify one mutation
            current_role["value"] = "admin"
            res = await client.put(f"/api/v1/policies/{policy_id}", json={"description": "Admin edit OK"})
            runner.assert_true(res.status_code == 200, "Admin can update policies")

            # Unauthenticated: no overrides
            saved_user = app.dependency_overrides.pop(get_current_user)
            saved_tenant = app.dependency_overrides.pop(get_tenant_context)
            try:
                res = await client.get("/api/v1/actions")
                runner.assert_true(res.status_code == 403, "Unauthenticated caller rejected (403)")
            finally:
                app.dependency_overrides[get_current_user] = saved_user
                app.dependency_overrides[get_tenant_context] = saved_tenant

            # -----------------------------------------------------------------
            # Group 8: Audit trail for management actions
            # -----------------------------------------------------------------
            print("\n[Phase 3.8] Audit Trail")
            async with async_session_maker() as db:
                logs = (await db.execute(
                    select(AuditLog).where(
                        AuditLog.organization_id == org_id,
                        AuditLog.action.in_([
                            "approve_action_execution", "reject_action_execution",
                            "release_quarantine", "unblock_item",
                            "update_enforcement_policy", "activate_enforcement_policy",
                        ]),
                    )
                )).scalars().all()
                logged_actions = {log.action for log in logs}
            runner.assert_true(
                {"approve_action_execution", "reject_action_execution", "release_quarantine",
                 "unblock_item", "update_enforcement_policy", "activate_enforcement_policy"}
                <= logged_actions,
                "All management actions written to the audit log",
                f"found={logged_actions}",
            )
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_tenant_context, None)
        current_user_id.set(None)


async def _standalone() -> int:
    runner = TestRunner()
    print("\n🛡️ STARTING CYBERGUARD PHASE 3 TEST SUITE\n" + "=" * 60)
    await run_phase3_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
