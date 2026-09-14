"""ORG-2 dashboards: org_log_events table, org-scoped RLS, realtime publication.

Revision ID: 0009_org_dashboards
Revises: 0008_org_foundation
Create Date: 2026-09-15

1. ``org_log_events`` (from live ORM metadata, checkfirst) — Splunk-style
   ingested logs with detector analysis, fed exclusively by the gateway.
2. RLS:
   - SELECT: org members (any role) via ``org_member_role()``.
   - UPDATE (``manual_action_taken``): analysts and admins.
   - INSERT: org admins (the gateway ingest runs under the org owner's RLS
     identity, which the owner fallback resolves to 'admin').
   - DELETE: org admins.
3. Realtime (best-effort, Supabase): ``org_log_events`` and ``alerts`` are
   added to the ``supabase_realtime`` publication when it exists (it does on
   Supabase; on plain Postgres there is nothing to subscribe to and the step
   is skipped silently). Row filter on organization_id requires PG15+; on
   older servers the tables are added without the filter.
4. Demo-tradeoff SELECT policies ``TO authenticated`` on ``org_log_events``
   and ``alerts``: the Supabase Realtime subscriber role must be able to read
   the rows it streams (app-role policies do not apply to that connection).
   Recorded in DECISIONS.md; tightening is tracked for ORG-5.

Downgrade drops only what this migration added.
"""
import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0009_org_dashboards"
down_revision: Union[str, Sequence[str], None] = "0008_org_foundation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_dashboards")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"


def _member_role_call(tbl: str) -> str:
    return f"cyberguard.org_member_role({tbl}.organization_id, {_GUC})"


def _create_log_events_table() -> None:
    import app.db.models  # noqa: F401 - populate Base.metadata
    from app.db.base import Base

    bind = op.get_bind()
    tables = [t for t in Base.metadata.sorted_tables if t.name == "org_log_events"]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)


def _replace_policy(table: str, policy: str, ddl: str) -> None:
    op.execute(f"DROP POLICY IF EXISTS {policy} ON {SCHEMA}.{table}")
    op.execute(ddl)


def _policies() -> None:
    tbl = f"{SCHEMA}.org_log_events"
    member = _member_role_call("org_log_events")

    _replace_policy(
        "org_log_events",
        "org_log_events_member_select",
        f"CREATE POLICY org_log_events_member_select ON {tbl} "
        f"FOR SELECT TO cyberguard_api USING ({member} IS NOT NULL)",
    )
    _replace_policy(
        "org_log_events",
        "org_log_events_admin_insert",
        f"CREATE POLICY org_log_events_admin_insert ON {tbl} "
        f"FOR INSERT TO cyberguard_api WITH CHECK ({member} = 'admin')",
    )
    _replace_policy(
        "org_log_events",
        "org_log_events_analyst_update",
        f"CREATE POLICY org_log_events_analyst_update ON {tbl} "
        f"FOR UPDATE TO cyberguard_api "
        f"USING ({member} IN ('admin', 'analyst')) "
        f"WITH CHECK ({member} IN ('admin', 'analyst'))",
    )
    _replace_policy(
        "org_log_events",
        "org_log_events_admin_delete",
        f"CREATE POLICY org_log_events_admin_delete ON {tbl} "
        f"FOR DELETE TO cyberguard_api USING ({member} = 'admin')",
    )
    # Realtime subscriber role (demo tradeoff — see DECISIONS.md).
    _replace_policy(
        "org_log_events",
        "org_log_events_authenticated_select",
        f"CREATE POLICY org_log_events_authenticated_select ON {tbl} "
        f"FOR SELECT TO authenticated USING (true)",
    )
    _replace_policy(
        "alerts",
        "alerts_authenticated_select",
        f"CREATE POLICY alerts_authenticated_select ON {SCHEMA}.alerts "
        f"FOR SELECT TO authenticated USING (true)",
    )


def _realtime_publication() -> None:
    """Add org_log_events + alerts to supabase_realtime when it exists.

    Pre-checks (publication exists, table not already a member, PG15+ for row
    filters) instead of try/except: under transactional DDL a failed statement
    would abort the whole migration transaction. Every skip is logged; on a
    plain Postgres instance without the publication this is a clean no-op.

    Row filter: only ``org_log_events`` gets ``WHERE (organization_id IS NOT
    NULL)`` — its organization_id is NOT NULL, and the column must be part of
    the table's REPLICA IDENTITY for UPDATE/DELETE publishes. ``alerts``
    allows NULL organization rows (personal workspace), so it is published
    unfiltered; subscribers still scope with ``filter: organization_id=eq.X``
    and the app-role policies do the real isolation.
    """
    bind = op.get_bind()
    has_pub = bind.execute(
        text("select 1 from pg_publication where pubname = 'supabase_realtime'")
    ).scalar()
    if not has_pub:
        logger.info("no supabase_realtime publication — realtime step skipped")
        return

    pg15_plus = bind.execute(text("show server_version_num")).scalar()
    row_filter = "WHERE (organization_id IS NOT NULL)" if int(pg15_plus) >= 150000 else ""

    if row_filter:
        op.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS uq_org_log_events_replica "
            f"ON {SCHEMA}.org_log_events (id, organization_id)"
        )
        op.execute(
            f"ALTER TABLE {SCHEMA}.org_log_events REPLICA IDENTITY USING INDEX uq_org_log_events_replica"
        )

    for table, filter_clause in (("org_log_events", row_filter), ("alerts", "")):
        already = bind.execute(
            text("select 1 from pg_publication_tables where pubname = 'supabase_realtime' "
                 "and schemaname = :schema and tablename = :table"),
            {"schema": SCHEMA, "table": table},
        ).scalar()
        if already:
            logger.info("%s already in supabase_realtime", table)
            continue
        op.execute(f"ALTER PUBLICATION supabase_realtime ADD TABLE {SCHEMA}.{table} {filter_clause}".strip())
        logger.info("added %s to supabase_realtime %s", table, filter_clause or "(unfiltered)")


def upgrade() -> None:
    _create_log_events_table()
    op.execute(f"ALTER TABLE {SCHEMA}.org_log_events ENABLE ROW LEVEL SECURITY")
    _policies()
    _realtime_publication()
    op.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA {SCHEMA} TO cyberguard_api")
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON TABLES TO cyberguard_api"
    )


def downgrade() -> None:
    bind = op.get_bind()
    has_pub = bind.execute(
        text("select 1 from pg_publication where pubname = 'supabase_realtime'")
    ).scalar()
    if has_pub:
        for table in ("org_log_events", "alerts"):
            op.execute(f"ALTER PUBLICATION supabase_realtime DROP TABLE {SCHEMA}.{table}")
    op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.org_log_events CASCADE")
    op.execute(f"DROP POLICY IF EXISTS alerts_authenticated_select ON {SCHEMA}.alerts")
    op.execute(f"ALTER TABLE {SCHEMA}.alerts REPLICA IDENTITY DEFAULT")
