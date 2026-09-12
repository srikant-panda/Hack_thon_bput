"""enforcement settings, quarantine and blocked senders

Revision ID: 0005_enforcement_settings
Revises: 0004_email_connectors
Create Date: 2026-09-13

Adds the Phase 4 enforcement store (cyberguard schema, RLS owner policies):
- connector_settings: per-connector quarantine expiry / permanent-delete /
  auto-quarantine configuration.
- quarantined_items: messages quarantined at Gmail (label-based), with the
  full Phase 3 ScanResult stored for review.
- blocked_senders: Gmail filter-based sender blocks with expiry support.

Extensions beyond the spec's column list (documented in DECISIONS.md):
owner_user_id denormalized on every row (RLS owner policies), last_error for
honest failure reporting, and updated_at on settings.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0005_enforcement_settings"
down_revision: Union[str, Sequence[str], None] = "0004_email_connectors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = "cyberguard"

OWNER_TABLES = ["connector_settings", "quarantined_items", "blocked_senders"]


def upgrade() -> None:
    op.create_table(
        "connector_settings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=False),
        sa.Column("quarantine_expiry_hours", sa.Integer(), nullable=True),
        sa.Column("permanent_delete_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("auto_quarantine_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("connector_id", name="uq_connector_settings_connector"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["cyberguard.email_connector_accounts.id"], ondelete="CASCADE"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_connector_settings_owner_user_id"), "connector_settings", ["owner_user_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_connector_settings_connector_id"), "connector_settings", ["connector_id"], unique=False, schema=SCHEMA)

    op.create_table(
        "quarantined_items",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=False),
        sa.Column("provider_message_id", sa.String(length=128), nullable=False),
        sa.Column("sender_email", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("scan_result_json", sa.JSON(), nullable=True),
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="quarantined"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["cyberguard.email_connector_accounts.id"], ondelete="CASCADE"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_quarantined_items_owner_user_id"), "quarantined_items", ["owner_user_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_quarantined_items_connector_id"), "quarantined_items", ["connector_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_quarantined_items_status"), "quarantined_items", ["status"], unique=False, schema=SCHEMA)

    op.create_table(
        "blocked_senders",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=False),
        sa.Column("sender_email", sa.String(length=255), nullable=False),
        sa.Column("provider_rule_id", sa.String(length=128), nullable=True),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="blocked"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["cyberguard.email_connector_accounts.id"], ondelete="CASCADE"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_blocked_senders_owner_user_id"), "blocked_senders", ["owner_user_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_blocked_senders_connector_id"), "blocked_senders", ["connector_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_blocked_senders_status"), "blocked_senders", ["status"], unique=False, schema=SCHEMA)

    for table in OWNER_TABLES:
        op.execute(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
        q = f"{SCHEMA}.{table}"
        pred = "owner_user_id = current_setting('app.user_id', true)::text"
        op.execute(f"CREATE POLICY {table}_select ON {q} FOR SELECT TO cyberguard_api USING ({pred})")
        op.execute(f"CREATE POLICY {table}_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({pred})")
        op.execute(f"CREATE POLICY {table}_update ON {q} FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})")
        op.execute(f"CREATE POLICY {table}_delete ON {q} FOR DELETE TO cyberguard_api USING ({pred})")

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
