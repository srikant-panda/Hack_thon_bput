"""event email notifications: user notification address + delivery log

Revision ID: 0007_notifications
Revises: 0006_security_history
Create Date: 2026-09-13

Phase 7:
- users.notification_email: the ONLY address system notifications ever go to
  (strictly separate from connected mailboxes).
- cyberguard.notification_logs: every notification attempt with the real
  delivery outcome. RLS owner policy, matching the existing pattern.

Extension to the spec's column list: `backend` (db_log | smtp) records how
the message was actually delivered — documented in DECISIONS.md.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0007_notifications"
down_revision: Union[str, Sequence[str], None] = "0006_security_history"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = "cyberguard"


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("notification_email", sa.String(length=255), nullable=True),
        schema=SCHEMA,
    )

    op.create_table(
        "notification_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("recipient_email", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("body_html", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("backend", sa.String(length=16), nullable=False, server_default="db_log"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_notification_logs_owner_user_id"), "notification_logs", ["owner_user_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_notification_logs_status"), "notification_logs", ["status"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_notification_logs_created_at"), "notification_logs", ["created_at"], unique=False, schema=SCHEMA)

    q = f"{SCHEMA}.notification_logs"
    pred = "owner_user_id = current_setting('app.user_id', true)::text"
    op.execute(f"ALTER TABLE {q} ENABLE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY notification_logs_select ON {q} FOR SELECT TO cyberguard_api USING ({pred})")
    op.execute(f"CREATE POLICY notification_logs_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY notification_logs_update ON {q} FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY notification_logs_delete ON {q} FOR DELETE TO cyberguard_api USING ({pred})")

    op.execute("GRANT ALL ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_api")


def downgrade() -> None:
    q = f"{SCHEMA}.notification_logs"
    op.execute(
        f"DO $$ DECLARE pol RECORD; BEGIN "
        f"FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = '{SCHEMA}' AND tablename = 'notification_logs' LOOP "
        f"EXECUTE format('DROP POLICY %I ON {q}', pol.policyname); END LOOP; END $$;"
    )
    op.execute(f"ALTER TABLE {q} DISABLE ROW LEVEL SECURITY")
    op.drop_table("notification_logs", schema=SCHEMA)
    op.drop_column("users", "notification_email", schema=SCHEMA)
