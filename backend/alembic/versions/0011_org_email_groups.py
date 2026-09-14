"""ORG-4 email groups: registered notification emails, event routing settings,
delivery logs + org-scoped RLS.

Revision ID: 0011_org_email_groups
Revises: 0010_org_mail_connectors
Create Date: 2026-09-15

Tables (from live ORM metadata, checkfirst):
- ``org_notification_emails``  — registered addresses grouped by role
  (unique org+email).
- ``org_notification_settings`` — per-event-type routing (min_role + enabled).
- ``org_notification_logs``    — per-event delivery log with per-recipient
  outcomes.

RLS (via ``cyberguard.org_member_role()``):
- emails / settings: SELECT admin+analyst (viewer blocked), writes admin.
- logs: SELECT admin+analyst (viewer blocked), writes admin (the service
  writes run under the org owner / admin identities; aggregation endpoints
  go through membership-gated routes).
"""

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0011_org_email_groups"
down_revision: Union[str, Sequence[str], None] = "0010_org_mail_connectors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_email_groups")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"

TABLES = ("org_notification_emails", "org_notification_settings", "org_notification_logs")


def _member_pred(tbl: str) -> str:
    return f"cyberguard.org_member_role({tbl}.organization_id, {_GUC})"


def _analyst_up_pred(tbl: str) -> str:
    return f"cyberguard.org_member_role({tbl}.organization_id, {_GUC}) IN ('admin', 'analyst')"


def _admin_pred(tbl: str) -> str:
    return f"cyberguard.org_member_role({tbl}.organization_id, {_GUC}) = 'admin'"


def _create_tables() -> None:
    import app.db.models  # noqa: F401 - populate Base.metadata
    from app.db.base import Base

    bind = op.get_bind()
    tables = [t for t in Base.metadata.sorted_tables if t.name in TABLES]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)


def _replace_policy(table: str, policy: str, ddl: str) -> None:
    op.execute(f"DROP POLICY IF EXISTS {policy} ON {SCHEMA}.{table}")
    op.execute(ddl)


def _policies() -> None:
    for table in TABLES:
        # Analysts read, viewers blocked, admins full (FOR ALL ORs with select).
        _replace_policy(
            table,
            f"{table}_select",
            f"CREATE POLICY {table}_select ON {SCHEMA}.{table} "
            f"FOR SELECT TO cyberguard_api USING ({_analyst_up_pred(table)})",
        )
        _replace_policy(
            table,
            f"{table}_admin_write",
            f"CREATE POLICY {table}_admin_write ON {SCHEMA}.{table} "
            f"FOR ALL TO cyberguard_api "
            f"USING ({_admin_pred(table)}) WITH CHECK ({_admin_pred(table)})",
        )


def upgrade() -> None:
    _create_tables()
    for table in TABLES:
        op.execute(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    _policies()
    op.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA {SCHEMA} TO cyberguard_api")
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON TABLES TO cyberguard_api"
    )


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.{table} CASCADE")
