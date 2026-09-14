"""Shared RLS test-harness helpers (Phase -1 baseline RLS compatibility).

The from-scratch baseline enforces row-level security on every table for the
app role (cyberguard_api, NOBYPASSRLS). Test fixtures that provision rows via
direct sessions must therefore:

1. Set the ``app.user_id`` GUC (via ``current_user_id``) to the row owner
   before the transaction begins — use :func:`as_user`.
2. Insert ``users`` rows through the service role (a user's row is only
   visible/writable under its OWN identity, so multi-user fixtures cannot
   provision them through the app role) — use :func:`create_user_admin`.
"""

from contextlib import asynccontextmanager

from app.db.session import current_user_id


@asynccontextmanager
async def as_user(user_id: str):
    """Set the RLS identity (app.user_id GUC) for the wrapped block."""
    current_user_id.set(user_id)
    try:
        yield
    finally:
        current_user_id.set(None)


async def create_user_admin(**user_fields) -> None:
    """Insert a users row through the service role (bypasses RLS)."""
    from app.db.admin import _get_admin_session_maker
    from app.db.models import User

    async with _get_admin_session_maker()() as session:
        session.add(User(**user_fields))
        await session.commit()
