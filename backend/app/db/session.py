"""Database engine, session management, and startup initialization."""

import logging
from typing import AsyncGenerator

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.db.base import Base

logger = logging.getLogger("cyberguard.db")

settings = get_settings()

# Engine creation: supports asyncpg (PostgreSQL) and aiosqlite (SQLite)
connect_args = {}
if "sqlite" in settings.async_database_url:
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30

engine = create_async_engine(
    settings.async_database_url,
    echo=False,
    future=True,
    connect_args=connect_args,
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an AsyncSession."""
    async with async_session_maker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


DEFAULT_RESPONSE_CATALOG = [
    {
        "action": "Block suspicious URL",
        "target_type": "url",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Add the URL to the blocklist and deny access from managed endpoints.",
    },
    {
        "action": "Quarantine email",
        "target_type": "email",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Move the suspicious email out of user inboxes into quarantine.",
    },
    {
        "action": "Warn the user",
        "target_type": "user",
        "automation_level": "automatic",
        "requires_approval": False,
        "description": "Notify the targeted user about the threat and safe handling steps.",
    },
    {
        "action": "Require additional authentication",
        "target_type": "session",
        "automation_level": "automatic",
        "requires_approval": False,
        "description": "Force step-up authentication (e.g. MFA) for the affected account.",
    },
    {
        "action": "Revoke active session",
        "target_type": "session",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Terminate the suspicious session and force re-authentication.",
    },
    {
        "action": "Block suspicious IP/device",
        "target_type": "network",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Block the flagged IP address or device identifier at the perimeter.",
    },
    {
        "action": "Flag multimedia for manual verification",
        "target_type": "media",
        "automation_level": "manual",
        "requires_approval": False,
        "description": "Mark the media item for human review by an analyst.",
    },
    {
        "action": "Report impersonation",
        "target_type": "external",
        "automation_level": "manual",
        "requires_approval": False,
        "description": "Report the impersonation attempt to the affected brand or platform.",
    },
    {
        "action": "Notify administrator/SOC",
        "target_type": "notification",
        "automation_level": "automatic",
        "requires_approval": False,
        "description": "Send an alert to the administrator or SOC channel for triage.",
    },
    {
        "action": "Escalate the incident for investigation",
        "target_type": "incident",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Escalate the incident to senior analysts for deeper investigation.",
    },
]


async def _seed_default_policies() -> None:
    """Create one default "Balanced" enforcement policy per organization if none exists."""
    from app.db.models import EnforcementPolicy, Organization

    async with async_session_maker() as session:
        result = await session.execute(select(Organization))
        orgs = result.scalars().all()

        seeded = 0
        for org in orgs:
            existing = await session.execute(
                select(EnforcementPolicy).where(
                    EnforcementPolicy.organization_id == org.id,
                    EnforcementPolicy.is_active == True,  # noqa: E712 - SQLAlchemy comparison
                )
            )
            if existing.scalars().first() is not None:
                continue

            session.add(EnforcementPolicy(
                organization_id=org.id,
                name="Balanced (default)",
                description="Auto-block critical/high, require approval for medium.",
                is_active=True,
            ))
            seeded += 1

        if seeded:
            logger.info("Seeded default enforcement policies for %d organization(s)...", seeded)
            await session.commit()


async def init_db() -> None:
    """Initialize database tables and seed default records if needed."""
    from app.db.models import ResponseCatalog

    logger.info("Initializing database schema on %s...", settings.async_database_url.split("@")[-1])
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed response catalog
    async with async_session_maker() as session:
        result = await session.execute(select(ResponseCatalog).limit(1))
        if not result.scalars().first():
            logger.info("Seeding default response catalog actions...")
            for item in DEFAULT_RESPONSE_CATALOG:
                session.add(ResponseCatalog(**item))
            await session.commit()

    # Seed one default enforcement policy per organization (no-op when no orgs exist yet)
    await _seed_default_policies()
