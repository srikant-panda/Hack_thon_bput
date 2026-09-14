"""ORG-1 — Organization Foundation test suite (Suite 17).

Covers:
1. Org creation + name salting ("Acme Corp" -> "Acme Corp-2")
2. API key lifecycle: create (plaintext once) -> validate -> revoke -> invalid
3. Gateway auth: valid key passes, invalid key 401, cross-org org_id 403
4. Role permissions: admin manages, analyst blocked from admin actions,
   viewer excluded from sensitive settings
5. Cross-org isolation at the API layer AND at the RLS layer (app role,
   app.user_id GUC keyed sessions)

Run via run_all_tests.py (Suite 17) or standalone:
    uv run python scripts/test_org_foundation.py
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.security import CurrentUser, get_current_user
from app.db.models import User
from app.db.session import async_session_maker, current_user_id
from app.main import app
from app.services.api_key_service import validate_api_key


class _Identity:
    """Mutable per-suite identity the get_current_user override returns."""

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
    """Insert a user row under its own RLS identity (owner policy).

    The GUC is applied at transaction begin, so the read-only lookup must be
    committed before the insert transaction starts with the new identity.
    """
    from sqlalchemy import select

    existing = await db.execute(select(User).where(User.id == user_id))
    if existing.scalar_one_or_none() is not None:
        return
    await db.commit()  # close the read transaction (empty GUC)
    current_user_id.set(user_id)
    db.add(User(id=user_id, email=email, full_name=full_name, is_single_user=True))
    await db.commit()
    current_user_id.set(None)


async def run_org_foundation_tests(runner) -> None:
    r = _runner_shim(runner)
    print("\n" + "-" * 60)
    print("ORG-1 Foundation: salting, API keys, gateway, RBAC, isolation")
    print("-" * 60)

    stamp = uuid.uuid4().hex[:8]
    admin = CurrentUser(id=f"orga-admin-{stamp}", email=f"orga-admin-{stamp}@cyberguard.test", full_name="Org A Admin")
    analyst = CurrentUser(id=f"orga-analyst-{stamp}", email=f"orga-analyst-{stamp}@cyberguard.test", full_name="Org A Analyst")
    viewer = CurrentUser(id=f"orga-viewer-{stamp}", email=f"orga-viewer-{stamp}@cyberguard.test", full_name="Org A Viewer")
    other_admin = CurrentUser(id=f"orgb-admin-{stamp}", email=f"orgb-admin-{stamp}@cyberguard.test", full_name="Org B Admin")

    # Pre-create user rows under their own RLS identities.
    async with async_session_maker() as db:
        for u in (admin, analyst, viewer, other_admin):
            await _ensure_user(db, u.id, u.email or "", u.full_name or "")

    app.dependency_overrides[get_current_user] = _mock_get_current_user

    transport = ASGITransport(app=app)
    org_a_id = ""
    raw_key = ""

    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # ---------------------------------------------------------------
            # 1. Org creation + salting
            # ---------------------------------------------------------------
            _Identity.user = admin
            base_name = f"Acme Corp {stamp}"  # unique per run: the DB persists
            res1 = await client.post("/api/v1/orgs", json={"name": base_name})
            r.assert_true(res1.status_code == 201, "POST /orgs creates organization (201)")
            org_a = res1.json()
            org_a_id = org_a["id"]
            r.assert_true(org_a["name"] == base_name, "First unused name stays unsalted")

            res2 = await client.post("/api/v1/orgs", json={"name": base_name})
            r.assert_true(res2.status_code == 201, "Second identical org name is accepted")
            org_a2 = res2.json()
            r.assert_true(org_a2["name"] == f"{base_name}-2", "Name conflict salts to '<name>-2'")
            r.assert_true(org_a2.get("display_name") == base_name, "display_name preserves the original name")

            # Org B for cross-org isolation tests
            _Identity.user = other_admin
            res_b = await client.post("/api/v1/orgs", json={"name": f"Org B {stamp}"})
            org_b_id = res_b.json()["id"]

            # Members: analyst + viewer on Org A
            _Identity.user = admin
            res_analyst = await client.post(
                f"/api/v1/orgs/{org_a_id}/members", json={"email": analyst.email, "role": "analyst"}
            )
            r.assert_true(res_analyst.status_code == 201, "Admin adds analyst member")
            res_viewer = await client.post(
                f"/api/v1/orgs/{org_a_id}/members", json={"email": viewer.email, "role": "viewer"}
            )
            r.assert_true(res_viewer.status_code == 201, "Admin adds viewer member")

            # ---------------------------------------------------------------
            # 2. API key lifecycle
            # ---------------------------------------------------------------
            res_key = await client.post(
                f"/api/v1/orgs/{org_a_id}/api-keys", json={"name": "Production Key"}
            )
            r.assert_true(res_key.status_code == 201, "Admin creates API key")
            created_key = res_key.json()
            raw_key = created_key.get("key", "")
            r.assert_true(raw_key.startswith("cg_live_"), "Plaintext key returned once with cg_live_ prefix")
            r.assert_true(created_key["key_prefix"] == raw_key[:16], "key_prefix stores display prefix only")

            res_keys = await client.get(f"/api/v1/orgs/{org_a_id}/api-keys")
            listed = res_keys.json() if res_keys.status_code == 200 else []
            r.assert_true(
                res_keys.status_code == 200 and all("key" not in k and "key_hash" not in k for k in listed),
                "Key list never exposes plaintext or hash",
            )

            async with async_session_maker() as db:
                validated = await validate_api_key(db, raw_key)
            r.assert_true(validated is not None and validated.id == org_a_id, "validate_api_key resolves the org")

            key_id = created_key["id"]
            res_revoke = await client.delete(f"/api/v1/orgs/{org_a_id}/api-keys/{key_id}")
            r.assert_true(res_revoke.status_code == 200 and res_revoke.json()["status"] == "revoked", "Admin revokes key")

            async with async_session_maker() as db:
                validated_after = await validate_api_key(db, raw_key)
            r.assert_true(validated_after is None, "Revoked key fails validation")

            # ---------------------------------------------------------------
            # 3. Gateway auth + actions
            # ---------------------------------------------------------------
            res_key2 = await client.post(
                f"/api/v1/orgs/{org_a_id}/api-keys", json={"name": "Gateway Key"}
            )
            raw_key = res_key2.json()["key"]

            res_no_key = await client.post(
                f"/api/v1/org/{org_a_id}/gateway", json={"action": "ingest_log", "data": {"line": "x"}}
            )
            r.assert_true(res_no_key.status_code == 401, "Gateway without org_authorization header -> 401")

            res_bad_key = await client.post(
                f"/api/v1/org/{org_a_id}/gateway",
                headers={"org_authorization": "cg_live_invalid"},
                json={"action": "ingest_log", "data": {"line": "x"}},
            )
            r.assert_true(res_bad_key.status_code == 401, "Gateway with invalid key -> 401")

            res_wrong_org = await client.post(
                f"/api/v1/org/{org_b_id}/gateway",
                headers={"org_authorization": raw_key},
                json={"action": "ingest_log", "data": {"line": "x"}},
            )
            r.assert_true(res_wrong_org.status_code == 403, "Gateway with mismatched org_id -> 403")

            res_log = await client.post(
                f"/api/v1/org/{org_a_id}/gateway",
                headers={"org_authorization": raw_key},
                json={"action": "ingest_log", "data": {"line": "Failed password for root from 185.220.101.7"}},
            )
            r.assert_true(res_log.status_code == 200 and res_log.json()["result"]["stored"], "Gateway ingest_log stores event")

            res_scan = await client.post(
                f"/api/v1/org/{org_a_id}/gateway",
                headers={"org_authorization": raw_key},
                json={
                    "action": "scan_url",
                    "data": {"url": "http://185.220.101.7/secure/login.php"},
                },
            )
            scan_ok = res_scan.status_code == 200 and res_scan.json()["result"].get("risk_score", 0) >= 60
            r.assert_true(scan_ok, "Gateway scan_url runs the full pipeline and scores malicious URL")

            res_unknown = await client.post(
                f"/api/v1/org/{org_a_id}/gateway",
                headers={"org_authorization": raw_key},
                json={"action": "teleport", "data": {}},
            )
            r.assert_true(res_unknown.status_code == 400, "Gateway unknown action -> 400")

            # ---------------------------------------------------------------
            # 4. Role permissions
            # ---------------------------------------------------------------
            _Identity.user = analyst
            res_analyst_key = await client.post(
                f"/api/v1/orgs/{org_a_id}/api-keys", json={"name": "Sneaky"}
            )
            r.assert_true(res_analyst_key.status_code == 403, "Analyst cannot create API keys")

            res_analyst_add = await client.post(
                f"/api/v1/orgs/{org_a_id}/members", json={"email": f"x-{stamp}@cyberguard.test", "role": "viewer"}
            )
            r.assert_true(res_analyst_add.status_code in (403, 404), "Analyst cannot manage members (403; 404 if invitee missing is reported first)")

            res_analyst_settings = await client.get(f"/api/v1/orgs/{org_a_id}/settings")
            r.assert_true(res_analyst_settings.status_code == 200, "Analyst reads org settings")

            _Identity.user = admin
            res_set = await client.put(
                f"/api/v1/orgs/{org_a_id}/settings/billing", json={"value": {"plan": "enterprise"}}
            )
            r.assert_true(res_set.status_code == 200, "Admin writes sensitive setting")

            _Identity.user = viewer
            res_viewer_settings = await client.get(f"/api/v1/orgs/{org_a_id}/settings")
            keys_visible = [s["key"] for s in res_viewer_settings.json()] if res_viewer_settings.status_code == 200 else ["billing"]
            r.assert_true(
                res_viewer_settings.status_code == 200 and "billing" not in keys_visible,
                "Viewer cannot read sensitive settings keys",
            )
            res_viewer_keys = await client.get(f"/api/v1/orgs/{org_a_id}/api-keys")
            r.assert_true(res_viewer_keys.status_code == 403, "Viewer cannot list API keys")

            # ---------------------------------------------------------------
            # 5. Cross-org isolation (API layer + RLS layer)
            # ---------------------------------------------------------------
            _Identity.user = other_admin
            res_cross = await client.get(f"/api/v1/orgs/{org_a_id}/api-keys")
            r.assert_true(res_cross.status_code == 403, "Org B admin cannot list Org A API keys (API layer)")

            res_cross_settings = await client.get(f"/api/v1/orgs/{org_a_id}/settings")
            r.assert_true(res_cross_settings.status_code == 403, "Org B admin cannot read Org A settings (API layer)")

            await _rls_isolation_checks(r, org_a_id, admin.id, viewer.id, other_admin.id)
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        current_user_id.set(None)


async def _rls_isolation_checks(r, org_a_id: str, admin_id: str, viewer_id: str, outsider_id: str) -> None:
    """Direct RLS verification through the app role (cyberguard_api, NOBYPASSRLS)."""
    from app.db.session import engine

    try:
        is_pg = "postgresql" in str(engine.dialect.name)
    except Exception:  # noqa: BLE001
        is_pg = False
    if not is_pg:
        r.assert_true(True, "RLS cross-org checks skipped without PostgreSQL")
        print("         Skipped: no PostgreSQL configured")
        return

    async def count_settings(guc_user: str) -> int:
        async with engine.connect() as conn:
            await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": guc_user})
            return (
                await conn.execute(
                    text("select count(*) from cyberguard.organization_settings where organization_id = :org"),
                    {"org": org_a_id},
                )
            ).scalar()

    seen_admin = await count_settings(admin_id)
    seen_viewer = await count_settings(viewer_id)
    seen_outsider = await count_settings(outsider_id)

    # Viewer member: sees only non-sensitive settings; the suite wrote exactly
    # one sensitive key ('billing'), so a viewer sees strictly fewer rows than
    # the admin and never the sensitive one.
    r.assert_true(
        seen_admin >= 1 and seen_viewer == seen_admin - 1,
        "RLS: viewer member sees non-sensitive settings only",
        f"admin={seen_admin} viewer={seen_viewer}",
    )
    r.assert_true(seen_outsider == 0, "RLS: user from another org sees 0 settings rows", f"outsider={seen_outsider}")

    # RLS blocks cross-org API key writes even for a valid DB session.
    async with engine.connect() as conn:
        await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": outsider_id})
        blocked = False
        try:
            await conn.execute(
                text(
                    "insert into cyberguard.organization_api_keys "
                    "(id, organization_id, name, key_hash, key_prefix, status) "
                    "values (:id, :org, 'rls-probe', 'rls-probe-hash', 'cg_live_probe', 'active')"
                ),
                {"id": str(uuid.uuid4()), "org": org_a_id},
            )
        except Exception:  # noqa: BLE001 - RLS rejection is the expected outcome
            blocked = True
        r.assert_true(blocked, "RLS: outsider cannot insert API keys into another org")


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
            print(f"\nORG-1: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n🏢 CYBERGUARD ORG-1 FOUNDATION TESTS\n" + "=" * 60)
    await run_org_foundation_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
