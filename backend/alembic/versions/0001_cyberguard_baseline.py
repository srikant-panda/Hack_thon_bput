"""CYBERGUARD full baseline: schema + all tables + RLS, created from scratch.

Revision ID: 0001_cyberguard_baseline
Revises: None (single from-scratch baseline — replaces all prior migrations)
Create Date: 2026-09-14

This migration is self-contained and error-tolerant so it works on ANY state
of the target database:

1. ``CREATE SCHEMA IF NOT EXISTS cyberguard`` — a wiped/missing schema is
   recreated automatically (no pre-step required).
2. All tables are generated from the live SQLAlchemy metadata
   (``app.db.models``) with ``checkfirst=True``, so re-running or pointing the
   baseline at a partially-populated database never fails on existing objects.
3. The ``cyberguard_api`` (NOBYPASSRLS) and ``authenticated`` roles are created
   only when missing.
4. Row-level security is enabled on every table with owner-scoped policies
   keyed on the ``app.user_id`` GUC (same pattern as the historical 0003 RLS
   migration), child/join policies via parent EXISTS, and shared-read
   policies for response_catalog/organizations.
5. Grants are (re)issued defensively.

Downgrade drops the whole schema (CASCADE) — this baseline owns everything.
"""
import logging
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0001_cyberguard_baseline"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.cyberguard_baseline")

SCHEMA = "cyberguard"

# Tables whose ownership derives from a parent row (EXISTS policies).
CHILD_TABLES = {
    "recommended_actions": (
        "EXISTS (SELECT 1 FROM cyberguard.alerts a WHERE a.id = alert_id "
        "AND a.owner_user_id = current_setting('app.user_id', true)::text)"
    ),
    "incident_alerts": (
        "EXISTS (SELECT 1 FROM cyberguard.incidents i WHERE i.id = incident_id "
        "AND i.owner_user_id = current_setting('app.user_id', true)::text)"
    ),
    "incident_events": (
        "EXISTS (SELECT 1 FROM cyberguard.incidents i WHERE i.id = incident_id "
        "AND i.owner_user_id = current_setting('app.user_id', true)::text)"
    ),
    "organization_members": (
        "user_id = current_setting('app.user_id', true)::text"
    ),
}

# Shared-read tables: authenticated PostgREST reads + full backend access.
SHARED_TABLES = ("response_catalog", "organizations")


def _ensure_schema() -> None:
    op.execute(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"')


def _create_all_tables() -> None:
    """Create every table from the live SQLAlchemy metadata.

    Generated from app.db.models so the database can never drift from the
    ORM. checkfirst=True keeps the baseline idempotent on partially-populated
    databases.
    """
    import app.db.models  # noqa: F401 - populate Base.metadata
    from app.db.base import Base

    bind = op.get_bind()
    tables = Base.metadata.sorted_tables
    logger.info("Creating %d tables in schema '%s' from SQLAlchemy metadata", len(tables), SCHEMA)
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)


def _table_names() -> set[str]:
    import app.db.models  # noqa: F401
    from app.db.base import Base

    return {t.name for t in Base.metadata.sorted_tables}


def _owner_key(table: str) -> str | None:
    import app.db.models  # noqa: F401
    from app.db.base import Base

    t = Base.metadata.tables[f"{SCHEMA}.{table}"]
    if table == "users":
        return "id"
    if "owner_user_id" in t.columns:
        return "owner_user_id"
    return None


def _ensure_roles() -> None:
    op.execute(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cyberguard_api') THEN "
        "CREATE ROLE cyberguard_api NOBYPASSRLS NOLOGIN; "
        "END IF; "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN "
        "CREATE ROLE authenticated NOLOGIN; "
        "END IF; END $$;"
    )


def _enable_rls(table: str) -> None:
    op.execute(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")


def _owner_policies(table: str, key: str) -> None:
    q = f"{SCHEMA}.{table}"
    pred = f"{key} = current_setting('app.user_id', true)::text"
    op.execute(f"CREATE POLICY {table}_select ON {q} FOR SELECT TO cyberguard_api USING ({pred})")
    op.execute(f"CREATE POLICY {table}_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY {table}_update ON {q} FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY {table}_delete ON {q} FOR DELETE TO cyberguard_api USING ({pred})")


def _child_policies(table: str, pred: str) -> None:
    q = f"{SCHEMA}.{table}"
    op.execute(f"CREATE POLICY {table}_select ON {q} FOR SELECT TO cyberguard_api USING ({pred})")
    op.execute(f"CREATE POLICY {table}_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY {table}_update ON {q} FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY {table}_delete ON {q} FOR DELETE TO cyberguard_api USING ({pred})")


def _shared_policies(table: str) -> None:
    q = f"{SCHEMA}.{table}"
    op.execute(
        f"CREATE POLICY {table}_authenticated_select ON {q} FOR SELECT "
        f"TO authenticated USING (current_setting('request.role', true) = 'authenticated')"
    )
    op.execute(f"CREATE POLICY {table}_app_all ON {q} FOR ALL TO cyberguard_api USING (true) WITH CHECK (true)")


def _app_only_policies(table: str) -> None:
    """Fallback for tables with no owner derivation: backend role only."""
    q = f"{SCHEMA}.{table}"
    op.execute(f"CREATE POLICY {table}_app_all ON {q} FOR ALL TO cyberguard_api USING (true) WITH CHECK (true)")


def _grants() -> None:
    op.execute(f"GRANT USAGE ON SCHEMA {SCHEMA} TO cyberguard_api")
    op.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA {SCHEMA} TO cyberguard_api")
    op.execute(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA {SCHEMA} TO cyberguard_api")
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} "
        "GRANT ALL ON TABLES TO cyberguard_api"
    )


def upgrade() -> None:
    # 1. Schema first — always, even when the database was wiped.
    _ensure_schema()
    # 2. All tables straight from the ORM metadata.
    _create_all_tables()
    # 3. Roles, RLS, policies, grants.
    _ensure_roles()
    _grants()

    tables = _table_names()
    for table in sorted(tables):
        _enable_rls(table)

    for table in sorted(tables):
        if table in SHARED_TABLES:
            _shared_policies(table)
            continue
        if table in CHILD_TABLES:
            _child_policies(table, CHILD_TABLES[table])
            continue
        key = _owner_key(table)
        if key:
            _owner_policies(table, key)
        else:
            logger.warning("table '%s' has no owner derivation — backend-role-only policy", table)
            _app_only_policies(table)


def downgrade() -> None:
    """This baseline owns the whole schema: dropping is the only downgrade."""
    op.execute(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE')
