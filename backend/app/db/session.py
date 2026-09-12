"""Database engine, session management, and startup initialization."""

import logging
from contextvars import ContextVar
from typing import AsyncGenerator, Optional

from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import SCHEMA, Base

logger = logging.getLogger("cyberguard.db")

settings = get_settings()

# Per-request identity used to satisfy PostgreSQL row-level security via the
# ``app.user_id`` GUC. Set by app.core.security once the bearer token is
# verified (which happens *after* get_db has yielded its session, hence the
# lazy per-transaction application below instead of a set_config at acquire).
current_user_id: ContextVar[Optional[str]] = ContextVar("current_user_id", default=None)

# Engine creation: supports asyncpg (PostgreSQL) and aiosqlite (SQLite)
connect_args = {}
is_sqlite = "sqlite" in settings.async_database_url
if is_sqlite:
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30

# SQLite has no schema support: every "cyberguard"-qualified table resolves to
# the default schema so the test suite runs unchanged. PostgreSQL uses the real
# dedicated schema.
engine_options = {}
if is_sqlite:
    engine_options["execution_options"] = {"schema_translate_map": {SCHEMA: None}}

engine = create_async_engine(
    settings.async_database_url,
    echo=False,
    future=True,
    connect_args=connect_args,
    **engine_options,
)

_GUC_SQL = text(
    "select set_config('app.user_id', :uid, false), set_config('request.role', :role, false)"
)
_GUC_RESET_SQL = text(
    "select set_config('app.user_id', '', false), set_config('request.role', '', false)"
)


def _is_postgres(session: Session) -> bool:
    bind = session.bind
    return bind is not None and bind.dialect.name == "postgresql"


@event.listens_for(Session, "after_begin")
def _apply_request_gucs(session: Session, transaction, connection) -> None:
    """Stamp app.user_id / request.role onto every new transaction (PG only)."""
    if not _is_postgres(session):
        return
    uid = current_user_id.get()
    connection.execute(
        _GUC_SQL,
        {"uid": uid or "", "role": "authenticated" if uid else ""},
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
            if _is_postgres(session):
                try:
                    await session.execute(_GUC_RESET_SQL)
                except Exception:  # noqa: S110 - reset is best-effort cleanup
                    pass
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
