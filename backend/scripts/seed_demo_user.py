"""Seed a demo user for local demos (clearly labeled — NOT production data).

Creates a demo account in the configured database (and, when possible, in
Supabase Auth):

    email    demo@cyberguard.local
    password demo1234!
    username demo

This script is OPTIONAL and never runs automatically. It exists only for
demo/hackathon setups; production deployments should not run it.

Usage:
    cd backend && uv run python scripts/seed_demo_user.py
"""

import asyncio
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DEMO_EMAIL = "demo@cyberguard.local"
DEMO_PASSWORD = "demo1234!"
DEMO_USERNAME = "demo"


async def seed_supabase_auth() -> str:
    """Create the demo identity in Supabase Auth (returns the auth user id)."""
    from supabase import create_client

    from app.core.config import get_settings

    settings = get_settings()
    client = create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)
    try:
        result = client.auth.sign_up(
            {
                "email": DEMO_EMAIL,
                "password": DEMO_PASSWORD,
                "options": {"data": {"full_name": "Demo Analyst", "username": DEMO_USERNAME}},
            }
        )
    except Exception as exc:  # noqa: BLE001
        print(f"  Supabase Auth signup failed (may already exist): {exc}")
        result = client.auth.sign_in_with_password(
            {"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
        )
    user = result.user
    if user is None:
        raise RuntimeError("Supabase Auth returned no user")
    return str(user.id)


async def seed_project_row(auth_id: str | None) -> None:
    from sqlalchemy import select

    from app.core.security import USERNAME_PATTERN
    from app.db.models import User
    from app.db.session import async_session_maker

    assert USERNAME_PATTERN.match(DEMO_USERNAME)

    async with async_session_maker() as db:
        existing = (
            await db.execute(select(User).where(User.username == DEMO_USERNAME))
        ).scalar_one_or_none()
        if existing:
            print(f"  Project user row already exists: {existing.id} ({existing.username})")
            return
        user = User(
            id=auth_id or f"demo-{DEMO_USERNAME}",
            email=DEMO_EMAIL,
            username=DEMO_USERNAME,
            account_type="user",
            full_name="Demo Analyst",
            is_single_user=True,
        )
        db.add(user)
        try:
            await db.commit()
            print(f"  Project user row created: {user.id}")
        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            print(f"  Could not create project user row ({exc}); run again with Supabase configured.")


async def main() -> int:
    print("\n⚠️  DEMO DATA SEEDER — creates demo@cyberguard.local / demo1234! (username: demo)")
    print("   Optional script for local demos; do NOT run in production.\n")
    auth_id = None
    try:
        auth_id = await seed_supabase_auth()
        print(f"  Supabase Auth identity ready: {auth_id}")
    except Exception as exc:  # noqa: BLE001
        print(f"  Skipping Supabase Auth ({exc}); creating local-only row.")
    await seed_project_row(auth_id)
    print("\nDone. Sign in with the username 'demo' or demo@cyberguard.local.\n")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
