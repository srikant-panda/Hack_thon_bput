"""email connectors: tables, indexes, RLS owner policies

Revision ID: 0004_email_connectors
Revises: 0003_rls
Create Date: 2026-09-13

Adds the Gmail connector foundation (Phase 1-2):
- email_connector_accounts: one mailbox connection per (owner, provider,
  provider_email); tokens stored encrypted (access_token_enc/refresh_token_enc).
- connector_oauth_states: single-use, expiring OAuth state rows; the callback
  (no bearer token) consumes them via the service-role helper.
- connector_operation_logs: honest audit trail of connector operations.
All tables live in the cyberguard schema with RLS owner policies keyed on
``app.user_id``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0004_email_connectors"
down_revision: Union[str, Sequence[str], None] = "0003_rls"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = "cyberguard"

OWNER_TABLES = ["email_connector_accounts", "connector_oauth_states", "connector_operation_logs"]


def upgrade() -> None:
    op.create_table(
        "email_connector_accounts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("provider_email", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="connected"),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=True),
        sa.Column("access_token_enc", sa.Text(), nullable=True),
        sa.Column("refresh_token_enc", sa.Text(), nullable=True),
        sa.Column("access_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_test_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_user_id", "provider", "provider_email", name="uq_connector_owner_provider_email"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_email_connector_accounts_owner_user_id"), "email_connector_accounts", ["owner_user_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_email_connector_accounts_status"), "email_connector_accounts", ["status"], unique=False, schema=SCHEMA)

    op.create_table(
        "connector_oauth_states",
        sa.Column("state", sa.String(length=128), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("redirect_after", sa.String(length=512), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("state"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_connector_oauth_states_owner_user_id"), "connector_oauth_states", ["owner_user_id"], unique=False, schema=SCHEMA)

    op.create_table(
        "connector_operation_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=True),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("provider_error_code", sa.String(length=128), nullable=True),
        sa.Column("provider_error_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["cyberguard.email_connector_accounts.id"], ondelete="SET NULL"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_connector_operation_logs_owner_user_id"), "connector_operation_logs", ["owner_user_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_connector_operation_logs_connector_id"), "connector_operation_logs", ["connector_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_connector_operation_logs_status"), "connector_operation_logs", ["status"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_connector_operation_logs_created_at"), "connector_operation_logs", ["created_at"], unique=False, schema=SCHEMA)

    # RLS: owner-scoped policies keyed on the app.user_id GUC.
    for table in OWNER_TABLES:
        op.execute(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
        q = f"{SCHEMA}.{table}"
        pred = "owner_user_id = current_setting('app.user_id', true)::text"
        op.execute(f"CREATE POLICY {table}_select ON {q} FOR SELECT TO cyberguard_api USING ({pred})")
        op.execute(f"CREATE POLICY {table}_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({pred})")
        op.execute(f"CREATE POLICY {table}_update ON {q} FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})")
        op.execute(f"CREATE POLICY {table}_delete ON {q} FOR DELETE TO cyberguard_api USING ({pred})")

    # Ensure the app role can use the new tables (created by the migration role).
    op.execute("GRANT ALL ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_api")


def downgrade() -> None:
    for table in OWNER_TABLES:
        q = f"{SCHEMA}.{table}"
        op.execute(
            f"DO $$ DECLARE pol RECORD; BEGIN "
            f"FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = '{SCHEMA}' AND tablename = '{table}' LOOP "
            f"EXECUTE format('DROP POLICY %I ON {q}', pol.policyname); END LOOP; END $$;"
        )
        op.execute(f"ALTER TABLE {q} DISABLE ROW LEVEL SECURITY")
        op.drop_table(table, schema=SCHEMA)
