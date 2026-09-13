"""trusted senders: user trust list that turns auto-enforcement recommend-only

Revision ID: 0008_trusted_senders
Revises: 0007_notifications
Create Date: 2026-09-14

FP-hardening (Deliverable 1):
- cyberguard.trusted_senders: senders the user explicitly trusts by releasing
  a message with "Release & trust sender" (or from the Blocked Senders page).
  Unique per (owner_user_id, sender_email). Scans still run for these senders;
  the action engine becomes recommend-only with an explicit annotation.
- RLS owner policy matching the existing pattern (app.user_id GUC).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0008_trusted_senders"
down_revision: Union[str, Sequence[str], None] = "0007_notifications"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = "cyberguard"


def upgrade() -> None:
    op.create_table(
        "trusted_senders",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("sender_email", sa.String(length=255), nullable=False),
        sa.Column("sender_domain", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["cyberguard.users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("owner_user_id", "sender_email", name="uq_trusted_sender_owner_email"),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_cyberguard_trusted_senders_owner_user_id"), "trusted_senders", ["owner_user_id"], unique=False, schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_trusted_senders_created_at"), "trusted_senders", ["created_at"], unique=False, schema=SCHEMA)

    q = f"{SCHEMA}.trusted_senders"
    pred = "owner_user_id = current_setting('app.user_id', true)::text"
    op.execute(f"ALTER TABLE {q} ENABLE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY trusted_senders_select ON {q} FOR SELECT TO cyberguard_api USING ({pred})")
    op.execute(f"CREATE POLICY trusted_senders_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY trusted_senders_update ON {q} FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})")
    op.execute(f"CREATE POLICY trusted_senders_delete ON {q} FOR DELETE TO cyberguard_api USING ({pred})")

    op.execute("GRANT ALL ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_api")


def downgrade() -> None:
    q = f"{SCHEMA}.trusted_senders"
    op.execute(
        f"DO $$ DECLARE pol RECORD; BEGIN "
        f"FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = '{SCHEMA}' AND tablename = 'trusted_senders' LOOP "
        f"EXECUTE format('DROP POLICY %I ON {q}', pol.policyname); END LOOP; END $$;"
    )
    op.execute(f"ALTER TABLE {q} DISABLE ROW LEVEL SECURITY")
    op.drop_table("trusted_senders", schema=SCHEMA)
