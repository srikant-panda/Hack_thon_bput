"""ORG-3 mail connectors: org_mail_servers, per-server settings and logs + RLS.

Revision ID: 0010_org_mail_connectors
Revises: 0009_org_dashboards
Create Date: 2026-09-15

Tables (from live ORM metadata, checkfirst):
- ``org_mail_servers`` — server-to-server connectors (google_workspace |
  microsoft_365 | imap_smtp); credentials stored Fernet-encrypted.
- ``org_mail_server_settings`` — per-server key/value config.
- ``org_mail_server_logs`` — per-server log streams (grouped BY server).

RLS (via ``cyberguard.org_member_role``, the ORG-1 SECURITY DEFINER function):
- ``org_mail_servers``: SELECT member (analyst+ per API layer), writes admin.
- ``org_mail_server_settings``: SELECT admin/analyst (viewer blocked),
  writes admin.
- ``org_mail_server_logs``: SELECT member, writes admin (API layer further
  restricts settings reads to analyst+ and writes to admin).
"""

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0010_org_mail_connectors"
down_revision: Union[str, Sequence[str], None] = "0009_org_dashboards"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_mail_connectors")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"


def _role_call(tbl: str) -> str:
    return f"cyberguard.org_member_role({tbl}.{_owner_col(tbl)}, {_GUC})"


def _owner_col(tbl: str) -> str:
    # Settings/logs hang off mail servers, not organizations directly —
    # resolve the org through the parent server row.
    if tbl == "org_mail_servers":
        return "organization_id"
    return "mail_server_id"


def _org_member_pred(tbl: str) -> str:
    """Membership predicate that reaches the owning organization.

    For settings/logs the org id lives on the parent ``org_mail_servers``
    row; join through it (org_mail_servers has no org-membership policy of
    its own that would recurse — its predicates use org_member_role on its
    own organization_id, which is the ORG-1 SECURITY DEFINER function and
    therefore safe).
    """
    if tbl == "org_mail_servers":
        return f"{_role_call(tbl)} IS NOT NULL"
    return (
        f"EXISTS (SELECT 1 FROM {SCHEMA}.org_mail_servers s "
        f"WHERE s.id = {tbl}.mail_server_id "
        f"AND cyberguard.org_member_role(s.organization_id, {_GUC}) IS NOT NULL)"
    )


def _org_admin_pred(tbl: str) -> str:
    if tbl == "org_mail_servers":
        return f"{_role_call(tbl)} = 'admin'"
    return (
        f"EXISTS (SELECT 1 FROM {SCHEMA}.org_mail_servers s "
        f"WHERE s.id = {tbl}.mail_server_id "
        f"AND cyberguard.org_member_role(s.organization_id, {_GUC}) = 'admin')"
    )


def _create_tables() -> None:
    import app.db.models  # noqa: F401 - populate Base.metadata
    from app.db.base import Base

    bind = op.get_bind()
    names = {"org_mail_servers", "org_mail_server_settings", "org_mail_server_logs"}
    tables = [t for t in Base.metadata.sorted_tables if t.name in names]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)


def _replace_policy(table: str, policy: str, ddl: str) -> None:
    op.execute(f"DROP POLICY IF EXISTS {policy} ON {SCHEMA}.{table}")
    op.execute(ddl)


def _policies() -> None:
    for table in ("org_mail_servers", "org_mail_server_settings", "org_mail_server_logs"):
        _replace_policy(
            table,
            f"{table}_select",
            f"CREATE POLICY {table}_select ON {SCHEMA}.{table} "
            f"FOR SELECT TO cyberguard_api USING ({_org_member_pred(table)})",
        )
        _replace_policy(
            table,
            f"{table}_admin_write",
            f"CREATE POLICY {table}_admin_write ON {SCHEMA}.{table} "
            f"FOR ALL TO cyberguard_api "
            f"USING ({_org_admin_pred(table)}) WITH CHECK ({_org_admin_pred(table)})",
        )

    # Settings: analysts read (viewer blocked) — select policy narrows to
    # admin/analyst roles; the admin FOR ALL above ORs in for admins.
    _replace_policy(
        "org_mail_server_settings",
        "org_mail_server_settings_analyst_select",
        f"CREATE POLICY org_mail_server_settings_analyst_select ON {SCHEMA}.org_mail_server_settings "
        f"FOR SELECT TO cyberguard_api USING ({_org_admin_pred('org_mail_server_settings')} OR ("
        f"{_org_member_pred('org_mail_server_settings')} "
        f"AND EXISTS (SELECT 1 FROM {SCHEMA}.org_mail_servers s2 "
        f"WHERE s2.id = org_mail_server_settings.mail_server_id "
        f"AND cyberguard.org_member_role(s2.organization_id, {_GUC}) IN ('admin', 'analyst'))))",
    )

    # Logs: every member may append via the service paths the backend uses,
    # but the API layer writes only through admin-gated routes; keep inserts
    # admin-scoped at RLS and reader-scoped to members.
    _replace_policy(
        "org_mail_server_logs",
        "org_mail_server_logs_member_select",
        f"CREATE POLICY org_mail_server_logs_member_select ON {SCHEMA}.org_mail_server_logs "
        f"FOR SELECT TO cyberguard_api USING ({_org_member_pred('org_mail_server_logs')})",
    )


def upgrade() -> None:
    _create_tables()
    for table in ("org_mail_servers", "org_mail_server_settings", "org_mail_server_logs"):
        op.execute(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    _policies()
    op.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA {SCHEMA} TO cyberguard_api")
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON TABLES TO cyberguard_api"
    )


def downgrade() -> None:
    op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.org_mail_server_logs CASCADE")
    op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.org_mail_server_settings CASCADE")
    op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.org_mail_servers CASCADE")
