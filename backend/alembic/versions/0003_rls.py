"""row-level security: owner-scoped policies keyed on app.user_id GUC

Revision ID: 0003_rls
Revises: 0002_user_foundation
Create Date: 2026-09-13

Enables RLS on every cyberguard table and installs:

- Owner-scoped tables: split SELECT/INSERT/UPDATE/DELETE policies on
  ``owner_user_id = current_setting('app.user_id', true)::text`` (``users``
  keys on ``id``). INSERT/UPDATE policies carry the matching WITH CHECK.
- Shared read tables (response_catalog, organizations): SELECT for the
  Supabase PostgREST roles via ``request.role = 'authenticated'``, plus a
  full-access policy for the backend's ``cyberguard_api`` role so startup
  seeding of the response catalog keeps working.
- Child/join tables: ownership derived from the parent row via EXISTS so
  RLS-enabled deny-all does not orphan them.

The application role (cyberguard_api) is NOBYPASSRLS: unauthenticated
requests run with an empty app.user_id and therefore see nothing.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_rls"
down_revision: Union[str, Sequence[str], None] = "0002_user_foundation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = "cyberguard"

# table -> owner key column
OWNER_TABLES = {
    "events": "owner_user_id",
    "alerts": "owner_user_id",
    "action_executions": "owner_user_id",
    "enforcement_policies": "owner_user_id",
    "audit_logs": "owner_user_id",
    "media_files": "owner_user_id",
    "incidents": "owner_user_id",
    "response_executions": "owner_user_id",
    "users": "id",
}

# child/join tables -> parent scoping predicate (EXISTS clause)
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
    # Backend role: response catalog is seeded at startup and organizations
    # must be resolvable in org mode; full access for the app role.
    op.execute(f"CREATE POLICY {table}_app_all ON {q} FOR ALL TO cyberguard_api USING (true) WITH CHECK (true)")


def upgrade() -> None:
    # Ensure the non-bypass application role exists. The cutover step then
    # only needs to enable login and set a password:
    #   ALTER ROLE cyberguard_api WITH LOGIN PASSWORD '<generated>';
    # "authenticated" mirrors the Supabase PostgREST role; created on vanilla
    # PostgreSQL so the shared-read policies install everywhere.
    op.execute(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cyberguard_api') THEN "
        "CREATE ROLE cyberguard_api NOBYPASSRLS NOLOGIN; "
        "END IF; "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN "
        "CREATE ROLE authenticated NOLOGIN; "
        "END IF; END $$;"
    )
    op.execute("GRANT USAGE ON SCHEMA cyberguard TO cyberguard_api")
    op.execute("GRANT ALL ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_api")
    op.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA cyberguard TO cyberguard_api")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA cyberguard "
        "GRANT ALL ON TABLES TO cyberguard_api"
    )

    # Enable RLS everywhere (deny-all by default for non-bypass roles).
    for table in list(OWNER_TABLES) + list(CHILD_TABLES) + ["response_catalog", "organizations"]:
        op.execute(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")

    for table, key in OWNER_TABLES.items():
        _owner_policies(table, key)
    for table, pred in CHILD_TABLES.items():
        _child_policies(table, pred)
    _shared_policies("response_catalog")
    _shared_policies("organizations")


def downgrade() -> None:
    for table in list(OWNER_TABLES) + list(CHILD_TABLES) + ["response_catalog", "organizations"]:
        q = f"{SCHEMA}.{table}"
        op.execute(
            f"DO $$ DECLARE pol RECORD; BEGIN "
            f"FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = '{SCHEMA}' AND tablename = '{table}' LOOP "
            f"EXECUTE format('DROP POLICY %I ON {q}', pol.policyname); END LOOP; END $$;"
        )
        op.execute(f"ALTER TABLE {q} DISABLE ROW LEVEL SECURITY")
