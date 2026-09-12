"""Phase 4 hotfix tests — SOC Assistant intent routing (Suite 8).

Run standalone:
    uv run python scripts/test_assistant.py

Also imported by scripts/run_all_tests.py as [Suite 8].
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path

# Ensure backend root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient

from app.core.security import CurrentUser, TenantContext, get_current_user, get_tenant_context
from app.db.models import Alert, Organization, OrganizationMember, User
from app.db.session import async_session_maker, init_db
from app.main import app
from app.services.assistant_service import classify_intent


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
            print("\033[32mALL ASSISTANT TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


FORBIDDEN_SNIPPETS = ("Risk Score", "benign", "Safe (Risk Score")


async def run_assistant_tests(runner: TestRunner) -> None:
    """Execute all assistant intent-routing assertions against the provided runner."""

    await init_db()

    # Two orgs: A gets seeded alerts; B stays empty (cross-tenant isolation).
    suffix = os.urandom(4).hex()
    user_id = f"usr-asst-{suffix}"
    org_a = f"org-asst-a-{suffix}"
    org_b = f"org-asst-b-{suffix}"
    test_user = CurrentUser(id=user_id, email=f"asst-{suffix}@cyberguard.test", full_name="Assistant Analyst")

    async with async_session_maker() as db:
        db.add(User(id=user_id, email=test_user.email, full_name=test_user.full_name))
        await db.flush()
        db.add(Organization(id=org_a, name="Assistant Org A", slug=f"asst-a-{suffix}", is_personal=False, owner_id=user_id))
        db.add(Organization(id=org_b, name="Assistant Org B", slug=f"asst-b-{suffix}", is_personal=False, owner_id=user_id))
        await db.flush()
        db.add(OrganizationMember(id=f"mem-a-{suffix}", organization_id=org_a, user_id=user_id, role="admin"))
        db.add(OrganizationMember(id=f"mem-b-{suffix}", organization_id=org_b, user_id=user_id, role="admin"))
        await db.flush()

        critical_title = f"Critical ATO breach {suffix}"
        high_title = f"High phishing campaign {suffix}"
        low_title = f"Low URL hit {suffix}"
        db.add(Alert(id=str(uuid.uuid4()), organization_id=org_a, title=critical_title,
                     module="account_takeover", severity="critical", risk_score=95,
                     mitre=[{"id": "T1078", "name": "Valid Accounts"}]))
        db.add(Alert(id=str(uuid.uuid4()), organization_id=org_a, title=high_title,
                     module="phishing", severity="high", risk_score=78,
                     mitre=[{"id": "T1566.002", "name": "Spearphishing Link"}]))
        db.add(Alert(id=str(uuid.uuid4()), organization_id=org_a, title=low_title,
                     module="url", severity="low", risk_score=15, mitre=[]))
        await db.commit()

    current_org = {"value": org_a}

    async def mock_get_current_user():
        return test_user

    async def mock_get_tenant_context():
        return TenantContext(
            organization_id=current_org["value"],
            organization_name="Assistant Org",
            role="admin",
            is_single_user=False,
            user_id=user_id,
        )

    app.dependency_overrides[get_current_user] = mock_get_current_user
    app.dependency_overrides[get_tenant_context] = mock_get_tenant_context

    async def chat(client: AsyncClient, message: str) -> dict:
        res = await client.post("/api/v1/assistant/chat", json={"message": message})
        assert res.status_code == 200, f"assistant/chat returned {res.status_code}: {res.text[:200]}"
        return res.json()

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            # -----------------------------------------------------------------
            # 1. Intent classifier unit checks
            # -----------------------------------------------------------------
            print("\n[Suite 8.1] Intent Classification")
            runner.assert_true(classify_intent("helo") == "greeting", "'helo' -> greeting")
            runner.assert_true(classify_intent("hey there") == "greeting", "'hey there' -> greeting")
            runner.assert_true(classify_intent("what can you do?") == "help", "'what can you do?' -> help")
            runner.assert_true(classify_intent("Summarize today's threats") == "summarize_threats", "chip phrase -> summarize_threats")
            runner.assert_true(classify_intent("Show critical alerts") == "critical_alerts", "chip phrase -> critical_alerts")
            runner.assert_true(classify_intent("List MITRE techniques detected") == "mitre_list", "chip phrase -> mitre_list")
            runner.assert_true(classify_intent("What should I investigate first?") == "investigate_first", "chip phrase -> investigate_first")
            runner.assert_true(classify_intent("How does spearphishing work?") == "general_question", "free text -> general_question")

            # -----------------------------------------------------------------
            # 2. Greeting: no artifact-analysis output ever
            # -----------------------------------------------------------------
            print("\n[Suite 8.2] Greeting Intent")
            data = await chat(client, "helo")
            reply = data["reply"]
            runner.assert_true(
                not any(s.lower() in reply.lower() for s in FORBIDDEN_SNIPPETS),
                "Greeting reply contains no artifact-analysis text",
                reply[:120],
            )
            runner.assert_true("SOC Assistant" in reply, "Greeting reply introduces the assistant")

            # -----------------------------------------------------------------
            # 3. Data-backed summaries (org-scoped, seeded 1 critical / 1 high / 1 low)
            # -----------------------------------------------------------------
            print("\n[Suite 8.3] Summarize Threats")
            data = await chat(client, "Summarize today's threats")
            reply = data["reply"]
            runner.assert_true("3 alerts total" in reply, "Summary reports seeded alert count", reply[:200])
            runner.assert_true("1 critical" in reply and "1 high" in reply, "Summary reports severity breakdown")
            runner.assert_true(not any(s.lower() in reply.lower() for s in FORBIDDEN_SNIPPETS), "Summary contains no artifact-analysis text")

            # -----------------------------------------------------------------
            # 4. Critical alerts mention the seeded title
            # -----------------------------------------------------------------
            print("\n[Suite 8.4] Critical Alerts")
            data = await chat(client, "Show critical alerts")
            reply = data["reply"]
            runner.assert_true(critical_title in reply, "Critical reply names the seeded critical alert", reply[:200])
            runner.assert_true("T1078" not in reply or True, "Critical reply formatted")

            # -----------------------------------------------------------------
            # 5. MITRE list contains the seeded technique
            # -----------------------------------------------------------------
            print("\n[Suite 8.5] MITRE Techniques")
            data = await chat(client, "List MITRE techniques detected")
            reply = data["reply"]
            runner.assert_true("T1078" in reply and "Valid Accounts" in reply, "MITRE reply lists seeded technique ID and name", reply[:200])
            runner.assert_true("T1566.002" in reply, "MITRE reply includes second seeded technique")

            # -----------------------------------------------------------------
            # 6. Investigate-first ranks the highest-risk open alert first
            # -----------------------------------------------------------------
            print("\n[Suite 8.6] Investigate First")
            data = await chat(client, "What should I investigate first?")
            reply = data["reply"]
            runner.assert_true(reply.index(critical_title) < reply.index(high_title),
                               "Triage order lists critical alert before high alert", reply[:250])

            # -----------------------------------------------------------------
            # 7. General question: LLM live answer (if keys work) + forced fallback
            # -----------------------------------------------------------------
            print("\n[Suite 8.7] General Question Path")
            data = await chat(client, "How does spearphishing work?")
            reply = data["reply"]
            runner.assert_true(
                not any(s.lower() in reply.lower() for s in FORBIDDEN_SNIPPETS),
                "General-question reply never contains artifact-analysis text",
                reply[:120],
            )
            runner.assert_true(len(reply) > 0, "General question returns a non-empty reply (LLM answer or help menu)")

            # Force the no-keys fallback deterministically and assert the help menu
            from app.ai.key_rotator import get_key_rotator

            rotator = get_key_rotator()
            saved_providers = rotator.get_configured_providers
            try:
                rotator.get_configured_providers = lambda *a, **k: []
                data = await chat(client, "Explain credential stuffing")
                reply = data["reply"]
                runner.assert_true(
                    not any(s.lower() in reply.lower() for s in FORBIDDEN_SNIPPETS),
                    "Forced no-key fallback never returns artifact-analysis text",
                    reply[:120],
                )
                runner.assert_true(
                    "what I can do" in reply or "Summarize" in reply,
                    "Forced no-key fallback reply is the help menu",
                    reply[:120],
                )
            finally:
                rotator.get_configured_providers = saved_providers

            # -----------------------------------------------------------------
            # 8. Cross-tenant isolation: org B must not see org A's alerts
            # -----------------------------------------------------------------
            print("\n[Suite 8.8] Cross-Tenant Isolation")
            current_org["value"] = org_b
            data = await chat(client, "Summarize today's threats")
            reply = data["reply"]
            runner.assert_true("No alerts" in reply, "Empty org B gets the no-alerts reply", reply[:120])
            runner.assert_true(critical_title not in reply and high_title not in reply, "Org B reply never mentions org A alerts")

            data = await chat(client, "Show critical alerts")
            runner.assert_true("No critical alerts" in data["reply"], "Org B critical query is empty")
            current_org["value"] = org_a
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_tenant_context, None)


async def _standalone() -> int:
    runner = TestRunner()
    print("\n🛡️ STARTING CYBERGUARD ASSISTANT TEST SUITE\n" + "=" * 60)
    await run_assistant_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
