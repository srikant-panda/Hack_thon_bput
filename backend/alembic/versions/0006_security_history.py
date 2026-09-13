"""security history: security_events table + audit_logs.actor_type

Revision ID: 0006_security_history
Revises: 0005_enforcement_settings
Create Date: 2026-09-13

Phase 5: permanent security history.
- cyberguard.security_events: one row per real security event / provider
  operation (scan verdicts, quarantine/release/keep/delete, sender rule
  lifecycle, connector lifecycle), with actor_type distinguishing user /
  system / scheduler and the REAL provider operation status.
- cyberguard.audit_logs.actor_type added (backfilled to 'user') so audit
  records distinguish automated vs user-initiated actions.

RLS: owner policy on app.user_id (existing pattern) + composite index
(owner_user_id, created_at desc).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0006_security_history"
down_revision: Union[str, Sequence[str], None] = "0005_enforcement_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = "cyberguard"


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=True),
        sa.Column("provider", sa.String(length=32), nullable=True),
        sa.Column("provider_message_id", sa.String(length=128), nullable=True),
        sa.Column("sender_email", sa.String(length=255), nullable=True),
        sa.Column("subject", sa.String(length=255), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("indicators", sa.JSON(), nullable=True),
        sa.Column("action_requested", sa.String(length=64), nullable=True),
        sa.Column("action_performed", sa.String(length=64), nullable=True),
        sa.Column("actor_type", sa.String(length=16), nullable=False, server_default="user"),
        sa.Column("operation_status", sa.String(length=32), nullable=True),
        sa.Column("operation_detail", sa.Text(), nullable=True),
        sa.Column("quarantined_item_id", sa.String(length=36), nullable=True),
        sa.Column("blocked_sender_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["cyberguard.email_connector_accounts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["quarantined_item_id"], ["cyberguard.quarantined_items.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["blocked_sender_id"], ["cyberguard.blocked_senders.id"], ondelete="SET NULL"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_security_events_owner_user_id"), "security_events", ["owner_user_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_security_events_event_type"), "security_events", ["event_type"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_security_events_provider_message_id"), "security_events", ["provider_message_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_security_events_actor_type"), "security_events", ["actor_type"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_security_events_created_at"), "security_events", ["created_at"], unique=False, schema=SCHEMA)
    # Review queries: newest events per owner first.
    op.create_index(
        "ix_cyberguard_security_events_owner_created",
        "security_events",
        ["owner_user_id", sa.text("created_at DESC")],
        unique=False,
        schema=SCHEMA,
    )

    # audit_logs.actor_type — automated vs user-initiated distinction.
    op.add_column(
        "audit_logs",
        sa.Column("actor_type", sa.String(length=16), nullable=False, server_default="user"),
        schema=SCHEMA,
    )
    op.execute(f"UPDATE {SCHEMA}.audit_logs SET actor_type = 'user' WHERE actor_type IS NULL")

    # RLS owner policy (existing pattern).
    q = f"{SCHEMA}.security_events"
    pred = "owner_user_id = current_setting('app.user_id', true)::text"
    op.execute(f"ALTER TABLE {q} ENABLE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY security_events_select ON {q} FOR SELECT TO cyberguard_api USING ({pred})")
    op.execute(f"CREATE POLICY security_events_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY security_events_update ON {q} FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY security_events_delete ON {q} FOR DELETE TO cyberguard_api USING ({pred})")

    op.execute("GRANT ALL ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_api")


def downgrade() -> None:
    q = f"{SCHEMA}.security_events"
    op.execute(
        f"DO $$ DECLARE pol RECORD; BEGIN "
        f"FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = '{SCHEMA}' AND tablename = 'security_events' LOOP "
        f"EXECUTE format('DROP POLICY %I ON {q}', pol.policyname); END LOOP; END $$;"
    )
    op.execute(f"ALTER TABLE {q} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_cyberguard_security_events_owner_created", table_name="security_events", schema=SCHEMA)
    op.drop_table("security_events", schema=SCHEMA)
    op.drop_column("audit_logs", "actor_type", schema=SCHEMA)
