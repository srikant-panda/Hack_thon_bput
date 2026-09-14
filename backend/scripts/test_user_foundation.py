"""Phase -1 suite: user-only account foundation.

Covers:
- username uniqueness (DB constraint + signup API)
- sign-in by username (server-side resolution to email)
- OAuth/JIT user-row consistency (unique auto-generated username, no duplicates)
- frozen organization endpoints (501 coming soon)
- cross-user data isolation through the API (owner-scoped tenancy)
- tenant_criteria unit cases
- alembic round-trip (skipped without a PostgreSQL MIGRATION_DATABASE_URL)
"""

import asyncio
import os
import sys
import uuid
from types import SimpleNamespace
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.core.security import TenantContext, get_current_user, get_tenant_context, tenant_criteria  # noqa: E402
from app.db.models import Alert, User  # noqa: E402
from app.db.session import async_session_maker  # noqa: E402
from functools import partial  # noqa: E402

from _rls import as_user, create_user_admin  # noqa: E402
from app.db.session import current_user_id  # noqa: E402
from app.main import app  # noqa: E402

# ---------------------------------------------------------------------------
# Supabase anon-client fake: the backend calls auth.sign_up /
# sign_in_with_password / get_user on it.
# ---------------------------------------------------------------------------

class _FakeAuth:
    def __init__(self) -> None:
        self.identities: dict[str, dict[str, Any]] = {}
        self.password_grants: list[str] = []
        self.get_user_tokens: list[str] = []

    def sign_up(self, payload: dict[str, Any]) -> Any:
        email = payload["email"]
        if email in self.identities:
            raise RuntimeError("User already registered")
        user_id = f"sb-{uuid.uuid4().hex[:12]}"
        self.identities[email] = {
            "id": user_id,
            "email": email,
            "password": payload["password"],
            "user_metadata": payload.get("options", {}).get("data", {}),
            "email_confirmed_at": None,
        }
        session = SimpleNamespace(
            access_token=f"sb-token-{user_id}",
            refresh_token=f"sb-refresh-{user_id}",
            expires_in=3600,
            token_type="bearer",
            user=self._user(email),
        )
        return SimpleNamespace(user=self._user(email), session=session)

    def sign_in_with_password(self, payload: dict[str, Any]) -> Any:
        email = payload["email"]
        self.password_grants.append(email)
        identity = self.identities.get(email)
        if identity is None or identity["password"] != payload["password"]:
            raise RuntimeError("Invalid login credentials")
        user_id = identity["id"]
        session = SimpleNamespace(
            access_token=f"sb-token-{user_id}",
            refresh_token=f"sb-refresh-{user_id}",
            expires_in=3600,
            token_type="bearer",
            user=self._user(email),
        )
        return SimpleNamespace(user=self._user(email), session=session)

    def get_user(self, token: str) -> Any:
        self.get_user_tokens.append(token)
        # token format: sb-token-<id> (issued by this fake) or plain <id>
        user_id = token.replace("sb-token-", "")
        for identity in self.identities.values():
            if identity["id"] == user_id:
                return SimpleNamespace(user=self._user(identity["email"]))
        raise RuntimeError("Invalid token")

    def _user(self, email: str) -> Any:
        identity = self.identities[email]
        return SimpleNamespace(
            id=identity["id"],
            email=identity["email"],
            user_metadata=identity["user_metadata"],
        )


_fake_auth = _FakeAuth()


def _install_fake_supabase() -> None:
    import app.core.security as security

    def _fake_client():
        return SimpleNamespace(auth=_fake_auth)

    security._get_anon_client = _fake_client


def _personal_tenant(user_id: str, email: str | None = None) -> TenantContext:
    # Overriding get_tenant_context bypasses the get_current_user subtree, so
    # the RLS identity must be stamped here. NOTE: must be invoked from an
    # async override — sync dependencies run in a worker thread whose context
    # copy would not propagate the ContextVar to the handler.
    current_user_id.set(user_id)
    return TenantContext(
        user_id=user_id,
        user_email=email,
        owner_user_id=user_id,
        organization_id=None,
        organization_name="Personal Workspace",
        role="admin",
        is_single_user=True,
    )


async def personal_tenant_override(user_id: str, email: str | None = None) -> TenantContext:
    return _personal_tenant(user_id, email)


async def run_user_foundation_tests(runner) -> None:
    _install_fake_supabase()

    user_a_id = f"usr-a-{uuid.uuid4().hex[:8]}"
    user_b_id = f"usr-b-{uuid.uuid4().hex[:8]}"

    async def override_user_a():
        current_user_id.set(user_a_id)  # RLS identity, as in production
        return SimpleNamespace(id=user_a_id, email=f"{user_a_id}@cyberguard.test", full_name="User A", username=None, account_type="user")

    async def override_user_b():
        current_user_id.set(user_b_id)  # RLS identity, as in production
        return SimpleNamespace(id=user_b_id, email=f"{user_b_id}@cyberguard.test", full_name="User B", username=None, account_type="user")

    # ------------------------------------------------------------------
    # 9.1 Username uniqueness (DB constraint)
    # ------------------------------------------------------------------
    print("\n[Suite 9.1] Username uniqueness (DB)")
    suffix = uuid.uuid4().hex[:6]
    # Provision through the service role: each user's row is only writable
    # under its own RLS identity, so multi-user fixtures bypass via admin.
    await create_user_admin(id=f"u-dup-1-{suffix}", username=f"dup.user{suffix}",
                            email=f"dup1-{suffix}@test.local", is_single_user=True)
    try:
        await create_user_admin(id=f"u-dup-2-{suffix}", username=f"dup.user{suffix}",
                                email=f"dup2-{suffix}@test.local", is_single_user=True)
        runner.assert_true(False, "Duplicate username rejected by DB unique constraint", "no error raised")
    except IntegrityError:
        runner.assert_true(True, "Duplicate username rejected by DB unique constraint")
    except Exception as exc:  # noqa: BLE001
        runner.assert_true(False, "Duplicate username rejected by DB unique constraint", str(exc))

    # ------------------------------------------------------------------
    # 9.2 Signup API: creates user with username; duplicate username -> 409
    # ------------------------------------------------------------------
    print("\n[Suite 9.2] Signup API & username enforcement")
    username = f"newuser.{uuid.uuid4().hex[:6]}"
    overrides = {
        "email": f"{username}@example.com",
        "password": "supersecret123",
        "username": username,
        "full_name": "New Analyst",
    }
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
        res = await client.post("/api/v1/auth/signup", json=overrides)
        runner.assert_true(res.status_code == 200, "POST /auth/signup creates account", f"status={res.status_code} body={res.text[:200]}")
        data = res.json()
        runner.assert_true(data.get("user", {}).get("username") == username, "Signup returns the chosen username")

        # Duplicate username -> 409
        res_dup = await client.post(
            "/api/v1/auth/signup",
            json={**overrides, "email": f"other-{uuid.uuid4().hex[:6]}@example.com"},
        )
        runner.assert_true(res_dup.status_code == 409, "Signup with taken username returns 409", f"status={res_dup.status_code}")

        # Invalid username pattern -> 400
        res_bad = await client.post(
            "/api/v1/auth/signup",
            json={**overrides, "username": "Bad Username!", "email": f"x-{uuid.uuid4().hex[:6]}@example.com"},
        )
        runner.assert_true(res_bad.status_code in (400, 422), "Signup with invalid username pattern is rejected", f"status={res_bad.status_code}")

        # Availability endpoint
        res_avail = await client.get(f"/api/v1/auth/username-available?username={username}")
        runner.assert_true(res_avail.status_code == 200 and res_avail.json()["available"] is False, "username-available reports taken username")
        res_free = await client.get(f"/api/v1/auth/username-available?username=free.{uuid.uuid4().hex[:6]}")
        runner.assert_true(res_free.status_code == 200 and res_free.json()["available"] is True, "username-available reports free username")

    # ------------------------------------------------------------------
    # 9.3 Sign-in by username (server-side resolution)
    # ------------------------------------------------------------------
    print("\n[Suite 9.3] Sign-in by username")
    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
        res = await client.post(
            "/api/v1/auth/signin",
            json={"identifier": username, "password": "supersecret123"},
        )
        runner.assert_true(res.status_code == 200, "POST /auth/signin with username returns 200", f"status={res.status_code} body={res.text[:200]}")
        data = res.json()
        runner.assert_true(bool(data.get("access_token")), "Sign-in returns access token")
        runner.assert_true(
            _fake_auth.password_grants and _fake_auth.password_grants[-1] == overrides["email"],
            "Username was resolved server-side to the account email",
        )

        res_bad = await client.post(
            "/api/v1/auth/signin",
            json={"identifier": username, "password": "wrong-password"},
        )
        runner.assert_true(res_bad.status_code in (401, 403), "Wrong password is rejected", f"status={res_bad.status_code}")

    # ------------------------------------------------------------------
    # 9.4 OAuth / JIT row consistency (mocked get_user)
    # ------------------------------------------------------------------
    print("\n[Suite 9.4] OAuth JIT user-row consistency")
    oauth_email = f"oauth.user-{uuid.uuid4().hex[:6]}@example.com"
    oauth_user_id = f"sb-{uuid.uuid4().hex[:12]}"
    _fake_auth.identities[oauth_email] = {
        "id": oauth_user_id,
        "email": oauth_email,
        "password": "oauth-managed",
        "user_metadata": {"name": "OAuth User"},
        "email_confirmed_at": "2026-01-01T00:00:00Z",
    }

    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
        me1 = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer sb-token-{oauth_user_id}"})
        runner.assert_true(me1.status_code == 200, "OAuth token resolves through /auth/me", f"status={me1.status_code}")
        me2 = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer sb-token-{oauth_user_id}"})
        runner.assert_true(me2.status_code == 200, "Second OAuth request resolves cleanly")

        data = me2.json()
        runner.assert_true(data.get("id") == oauth_user_id, "OAuth identity maps to a single project user row")
        runner.assert_true(bool(data.get("username")), "OAuth user received an auto-generated username")
        runner.assert_true(data.get("org_enabled") is False, "/auth/me reports organizations frozen")
        runner.assert_true(data.get("active_organization") is None, "Personal tenant has no active organization")

    async with async_session_maker() as db:
        rows = (await db.execute(select(User).where(User.email == oauth_email))).scalars().all()
        runner.assert_true(len(rows) == 1, "No duplicate identity for the same verified email", f"rows={len(rows)}")

    # ------------------------------------------------------------------
    # 9.5 Frozen organization endpoints -> 501
    # ------------------------------------------------------------------
    print("\n[Suite 9.5] Organization endpoints frozen (501)")
    app.dependency_overrides[get_current_user] = override_user_a
    app.dependency_overrides[get_tenant_context] = partial(personal_tenant_override, user_a_id)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
        res_list = await client.get("/api/v1/organizations")
        runner.assert_true(res_list.status_code == 501, "GET /organizations returns 501 when frozen", f"status={res_list.status_code}")
        res_create = await client.post("/api/v1/organizations", json={"name": "Frozen SOC"})
        runner.assert_true(res_create.status_code == 501, "POST /organizations returns 501 when frozen", f"status={res_create.status_code}")
        res_switch = await client.post("/api/v1/auth/switch-org", json={"organization_id": "org-x"})
        runner.assert_true(res_switch.status_code == 501, "POST /auth/switch-org returns 501 when frozen", f"status={res_switch.status_code}")
        detail = res_list.json().get("detail")
        runner.assert_true(
            detail == "Organization accounts are coming soon.",
            "501 detail carries the coming-soon message",
            f"detail={detail!r}",
        )

    # ------------------------------------------------------------------
    # 9.6 Cross-user isolation via API (owner-scoped tenancy)
    # ------------------------------------------------------------------
    print("\n[Suite 9.6] Cross-user data isolation via API")
    alert_a_id = f"alert-a-{uuid.uuid4().hex[:8]}"
    async with as_user(user_a_id), async_session_maker() as db:
        db.add(
            Alert(
                id=alert_a_id,
                owner_user_id=user_a_id,
                organization_id=None,
                title="User A private alert",
                module="phishing",
                severity="high",
                risk_score=80,
                status="new",
                created_by=user_a_id,
            )
        )
        await db.commit()

    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
        # User B sees no alerts
        app.dependency_overrides[get_tenant_context] = partial(personal_tenant_override, user_b_id)
        res_b_list = await client.get("/api/v1/alerts")
        b_ids = [item["id"] for item in res_b_list.json() if isinstance(item, dict)]
        runner.assert_true(alert_a_id not in b_ids, "User B cannot list user A's alerts")
        res_b_get = await client.get(f"/api/v1/alerts/{alert_a_id}")
        runner.assert_true(res_b_get.status_code == 404, "User B cannot fetch user A's alert by ID", f"status={res_b_get.status_code}")

        # User A sees their own alert
        app.dependency_overrides[get_tenant_context] = partial(personal_tenant_override, user_a_id)
        res_a_list = await client.get("/api/v1/alerts")
        a_ids = [item["id"] for item in res_a_list.json() if isinstance(item, dict)]
        runner.assert_true(alert_a_id in a_ids, "User A sees their own alert")
        res_a_get = await client.get(f"/api/v1/alerts/{alert_a_id}")
        runner.assert_true(res_a_get.status_code == 200, "User A can fetch their alert by ID", f"status={res_a_get.status_code}")

    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_tenant_context, None)

    # ------------------------------------------------------------------
    # 9.7 tenant_criteria unit cases
    # ------------------------------------------------------------------
    print("\n[Suite 9.7] tenant_criteria unit cases")
    personal = _personal_tenant("usr-personal-1")
    crit_personal = tenant_criteria(Alert, personal)
    runner.assert_true(
        str(crit_personal) == str(Alert.owner_user_id == "usr-personal-1"),
        "Personal tenant filters by owner_user_id",
    )
    org_tenant = TenantContext(
        user_id="usr-org-1",
        organization_id="org-42",
        organization_name="Org",
        role="admin",
        is_single_user=False,
        owner_user_id="org-owner-9",
    )
    crit_org = tenant_criteria(Alert, org_tenant)
    runner.assert_true(
        str(crit_org) == str(Alert.organization_id == "org-42"),
        "Organization tenant filters by organization_id",
    )

    # ------------------------------------------------------------------
    # 9.8 Alembic round-trip (skipped without PostgreSQL)
    # ------------------------------------------------------------------
    print("\n[Suite 9.8] Alembic round-trip (PG only)")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if "postgresql" not in migration_url:
        runner.assert_true(True, "Alembic round-trip skipped (no PG MIGRATION_DATABASE_URL configured)")
        print("         SKIP: set MIGRATION_DATABASE_URL to a PostgreSQL DSN to enable")
    else:
        import subprocess

        env = {**os.environ, "MIGRATION_DATABASE_URL": migration_url}

        def _alembic(*args: str) -> None:
            subprocess.run(
                [sys.executable, "-m", "alembic", *args],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

        try:
            _alembic("upgrade", "head")
            _alembic("downgrade", "-1")
            _alembic("upgrade", "head")
            runner.assert_true(True, "alembic upgrade head -> downgrade -1 -> upgrade head passes")
        except subprocess.CalledProcessError as exc:
            runner.assert_true(
                False,
                "alembic upgrade head -> downgrade -1 -> upgrade head passes",
                exc.stderr[-400:] if exc.stderr else str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            runner.assert_true(False, "alembic upgrade head -> downgrade -1 -> upgrade head passes", str(exc))


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
            print("\033[32mALL USER FOUNDATION TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


async def _standalone() -> int:
    runner = TestRunner()
    print("\n🛡️ STARTING CYBERGUARD USER FOUNDATION TEST SUITE\n" + "=" * 60)
    await run_user_foundation_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
