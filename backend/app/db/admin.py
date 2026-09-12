"""Service-role database access for pre-authentication lookups.

Row-level security on ``cyberguard.users`` denies anonymous reads, so the two
lookup operations that must happen *before* a request is authenticated
(username availability, username → email resolution at sign-in) run on a
separate engine built from ``MIGRATION_DATABASE_URL`` (the service/postgres
role, which bypasses RLS). On SQLite (tests/local dev) there is no RLS and the
main database is used directly.
"""

import logging
from functools import lru_cache
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.db.admin")


def _to_async_url(url: str) -> str:
    url = (url or "").strip()
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


@lru_cache(maxsize=1)
def _get_admin_session_maker() -> async_sessionmaker:
    settings = get_settings()
    if "sqlite" in settings.async_database_url:
        # No RLS on SQLite (tests/local): admin lookups share the app database
        # so test runs stay deterministic regardless of MIGRATION_DATABASE_URL.
        # The schema-translate map resolves the "cyberguard" prefix.
        url = settings.async_database_url
        options = {
            "connect_args": {"check_same_thread": False},
            "execution_options": {"schema_translate_map": {"cyberguard": None}},
        }
    else:
        url = _to_async_url(settings.MIGRATION_DATABASE_URL or settings.DATABASE_URL)
        options = {}
    engine = create_async_engine(url, echo=False, future=True, **options)
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def is_username_taken(username: str) -> bool:
    """Return True when the username already exists (service-role lookup)."""
    from app.db.models import User

    async with _get_admin_session_maker()() as session:
        result = await session.execute(
            select(User.id).where(User.username == username).limit(1)
        )
        return result.scalar_one_or_none() is not None


async def resolve_email_for_identifier(identifier: str) -> Optional[str]:
    """Resolve a username (or bare email) to its account email (service-role lookup)."""
    from app.db.models import User

    async with _get_admin_session_maker()() as session:
        result = await session.execute(
            select(User.email).where(User.username == identifier).limit(1)
        )
        return result.scalar_one_or_none()
