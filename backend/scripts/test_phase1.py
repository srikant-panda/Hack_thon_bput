"""Phase 1 tests — Dual-Mode Foundation (EnforcementPolicy, ActionExecution, mode detection, enforcement engine).

Run standalone:
    uv run python scripts/test_phase1.py

Also imported by scripts/run_all_tests.py as [Suite 5].
"""

import asyncio
import os
import sys
from pathlib import Path

# Ensure backend root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import inspect, select

from app.core.mode_detector import (
    EnforcementPolicyLevel,
    OperationMode,
    resolve_mode,
)
from app.db.models import ActionExecution, Alert, EnforcementPolicy, Organization, User
from app.db.session import _seed_default_policies, async_session_maker, engine, init_db
from app.services.enforcement_engine import enforcement_engine


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
            print("\033[32mALL PHASE 1 TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


async def run_phase1_tests(runner: TestRunner) -> None:
    """Execute all Phase 1 assertions against the provided runner."""

    # -----------------------------------------------------------------------
    # 1. Model creation — new tables exist after init_db()
    # -----------------------------------------------------------------------
    print("\n[Phase 1.1] Database Models & Schema")
    try:
        await init_db()
        async with engine.connect() as conn:
            table_names = await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names())
        runner.assert_true(
            "enforcement_policies" in table_names,
            "enforcement_policies table created after init_db()",
        )
        runner.assert_true(
            "action_executions" in table_names,
            "action_executions table created after init_db()",
        )
    except Exception as e:  # pragma: no cover - surfaced as failures below
        runner.assert_true(False, "init_db() with new tables", str(e))

    # -----------------------------------------------------------------------
    # 2. Mode resolution
    # -----------------------------------------------------------------------
    print("\n[Phase 1.2] Mode Detection Utility")
    runner.assert_true(
        resolve_mode(explicit_mode="client").mode == OperationMode.CLIENT,
        "resolve_mode(explicit_mode='client') -> CLIENT",
    )
    runner.assert_true(
        resolve_mode(explicit_mode="server").mode == OperationMode.SERVER,
        "resolve_mode(explicit_mode='server') -> SERVER",
    )
    runner.assert_true(
        resolve_mode(source="email_gateway").mode == OperationMode.SERVER,
        "resolve_mode(source='email_gateway') auto-detects SERVER",
    )
    runner.assert_true(
        resolve_mode().mode == OperationMode.CLIENT,
        "resolve_mode() with no args defaults to CLIENT",
    )
    runner.assert_true(
        resolve_mode(explicit_mode="server", auto_execute=True).auto_execute is True,
        "resolve_mode(server, auto_execute=True) keeps auto_execute=True",
    )
    client_ctx = resolve_mode(explicit_mode="client", auto_execute=True)
    runner.assert_true(
        client_ctx.auto_execute is False,
        "resolve_mode(client, auto_execute=True) forces auto_execute=False",
    )
    runner.assert_true(
        resolve_mode(explicit_mode="server", policy_level="strict").policy_level
        == EnforcementPolicyLevel.STRICT,
        "resolve_mode(server, policy_level='strict') resolves policy level",
    )

    # -----------------------------------------------------------------------
    # 3. Default policy seeding (per-org, idempotent)
    # -----------------------------------------------------------------------
    print("\n[Phase 1.3] Default Policy Seeding")
    suffix = os.urandom(4).hex()
    async with async_session_maker() as db:
        db.add(User(id=f"usr-p1-{suffix}", email=f"phase1-{suffix}@cyberguard.test", full_name="Phase One"))
        await db.flush()
        db.add(Organization(
            id=f"org-p1-{suffix}",
            name="Phase One Test Org",
            slug=f"phase1-{suffix}",
            is_personal=False,
            owner_id=f"usr-p1-{suffix}",
        ))
        await db.commit()

    await _seed_default_policies()
    async with async_session_maker() as db:
        policies = (await db.execute(
            select(EnforcementPolicy).where(EnforcementPolicy.organization_id == f"org-p1-{suffix}")
        )).scalars().all()
        runner.assert_true(
            len(policies) == 1 and policies[0].is_active and policies[0].name == "Balanced (default)",
            "New organization gets exactly one active 'Balanced (default)' policy",
        )
        default_policy = policies[0]
        runner.assert_true(
            default_policy.phishing_high_threshold == 75
            and default_policy.phishing_medium_threshold == 40
            and default_policy.network_high_threshold == 70,
            "Default policy thresholds match spec defaults (phishing 75/40, network 70/50)",
        )

    await _seed_default_policies()  # second run must be a no-op
    async with async_session_maker() as db:
        count = len((await db.execute(
            select(EnforcementPolicy).where(EnforcementPolicy.organization_id == f"org-p1-{suffix}")
        )).scalars().all())
        runner.assert_true(count == 1, "Seeding is idempotent (second run creates nothing)")

    # -----------------------------------------------------------------------
    # 4-7. Enforcement engine scenarios (alerts in-memory; policies persisted
    # so mapped_column defaults are applied by the ORM at flush time)
    # -----------------------------------------------------------------------
    print("\n[Phase 1.4] Enforcement Decision Engine")
    async with async_session_maker() as db:
        balanced = EnforcementPolicy(organization_id=f"org-p1-{suffix}", name="Balanced (test)")
        strict_network = EnforcementPolicy(
            organization_id=f"org-p1-{suffix}",
            name="Strict network (test)",
            network_high_threshold=90,
        )
        db.add_all([balanced, strict_network])
        await db.commit()

    # 4. High-risk phishing, server mode, auto-execute requested
    high_alert = Alert(id=f"alert-p1-hi-{suffix}", module="phishing", severity="high", risk_score=87)
    d_high = enforcement_engine.evaluate(high_alert, balanced, OperationMode.SERVER, request_auto_execute=True)
    runner.assert_true(d_high.enforcement_severity == "high", "Phishing score 87 -> enforcement severity 'high'")
    runner.assert_true(d_high.action_type == "block", "High band maps to policy action 'block'")
    runner.assert_true(d_high.auto_execute is True, "Server mode + request_auto_execute=True -> auto_execute=True")

    # 5. Medium-risk phishing requiring approval
    med_alert = Alert(id=f"alert-p1-md-{suffix}", module="phishing", severity="medium", risk_score=55)
    d_med = enforcement_engine.evaluate(med_alert, balanced, OperationMode.SERVER, request_auto_execute=True)
    runner.assert_true(d_med.enforcement_severity == "medium", "Phishing score 55 -> enforcement severity 'medium'")
    runner.assert_true(d_med.action_type == "warn_and_log", "Medium band maps to policy action 'warn_and_log'")
    runner.assert_true(d_med.auto_execute is False, "Medium band policy auto_execute=False wins over request")
    runner.assert_true(d_med.requires_approval is True, "Medium non-allow action requires approval")

    # 6. Low-risk -> allow, no approval
    low_alert = Alert(id=f"alert-p1-lo-{suffix}", module="phishing", severity="low", risk_score=20)
    d_low = enforcement_engine.evaluate(low_alert, balanced, OperationMode.SERVER, request_auto_execute=True)
    runner.assert_true(d_low.enforcement_severity == "low", "Phishing score 20 -> enforcement severity 'low'")
    runner.assert_true(d_low.action_type == "allow", "Low band maps to policy action 'allow'")
    runner.assert_true(d_low.requires_approval is False, "'allow' action never requires approval")

    # 7. Client mode never enforces
    d_client = enforcement_engine.evaluate(high_alert, balanced, OperationMode.CLIENT, request_auto_execute=True)
    runner.assert_true(d_client.auto_execute is False, "Client mode never auto-executes (even high risk)")
    runner.assert_true(d_client.requires_approval is False, "Client mode records recommendation only (no approval)")

    # 8. Per-module thresholds are independent
    net_alert = Alert(id=f"alert-p1-net-{suffix}", module="network", severity="high", risk_score=80)
    d_net = enforcement_engine.evaluate(net_alert, strict_network, OperationMode.SERVER)
    runner.assert_true(
        d_net.enforcement_severity == "medium",
        "Custom network_high_threshold=90 downgrades network score 80 to 'medium'",
    )
    phish_alert = Alert(id=f"alert-p1-ph-{suffix}", module="phishing", severity="high", risk_score=80)
    d_phish = enforcement_engine.evaluate(phish_alert, strict_network, OperationMode.SERVER)
    runner.assert_true(
        d_phish.enforcement_severity == "high",
        "Phishing score 80 stays 'high' under same policy (thresholds independent)",
    )

    # Extra: critical band + notifications
    crit_alert = Alert(id=f"alert-p1-cr-{suffix}", module="network", severity="critical", risk_score=95)
    d_crit = enforcement_engine.evaluate(crit_alert, balanced, OperationMode.SERVER, request_auto_execute=True)
    runner.assert_true(d_crit.enforcement_severity == "critical", "Score >= 90 classified 'critical'")
    runner.assert_true(d_crit.action_type == "block_and_quarantine", "Critical band maps to 'block_and_quarantine'")
    runner.assert_true(d_crit.notify_soc is True, "Critical decisions notify the SOC")

    # -----------------------------------------------------------------------
    # 9. ActionExecution persistence round-trip
    # -----------------------------------------------------------------------
    print("\n[Phase 1.5] ActionExecution Persistence")
    async with async_session_maker() as db:
        db.add(Alert(
            id=f"alert-p1-rt-{suffix}",
            organization_id=f"org-p1-{suffix}",
            title="Phase One round-trip alert",
            module="phishing",
            severity="high",
            risk_score=87,
        ))
        await db.flush()
        db.add(ActionExecution(
            id=f"exec-p1-{suffix}",
            organization_id=f"org-p1-{suffix}",
            alert_id=f"alert-p1-rt-{suffix}",
            action_type="block",
            target={"email_id": f"eml-{suffix}", "recipient": "victim@corp.test"},
            execution_mode="server",
            triggered_by="api",
            triggered_by_id="email-gateway-01",
            requires_approval=True,
            risk_score=87,
            severity="high",
            threat_type="phishing",
            module="phishing",
            policy_id=default_policy.id,
        ))
        await db.commit()

    async with async_session_maker() as db:
        fetched = (await db.execute(
            select(ActionExecution).where(ActionExecution.id == f"exec-p1-{suffix}")
        )).scalar_one_or_none()
        runner.assert_true(fetched is not None, "ActionExecution row persisted and queryable")
        if fetched is not None:
            runner.assert_true(fetched.status == "pending", "Default status is 'pending'")
            runner.assert_true(fetched.target["recipient"] == "victim@corp.test", "JSON target round-trips")
            runner.assert_true(fetched.approved_by is None and fetched.executed_at is None, "Approval fields start empty")
            runner.assert_true(fetched.policy_id == default_policy.id, "Policy FK links to seeded policy")


async def _standalone() -> int:
    runner = TestRunner()
    print("\n🛡️ STARTING CYBERGUARD PHASE 1 TEST SUITE\n" + "=" * 60)
    await run_phase1_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
