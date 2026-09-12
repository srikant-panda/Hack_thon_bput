"""user foundation: usernames, account_type, owner_user_id scoping

Revision ID: 0002_user_foundation
Revises: 1284c90c101c
Create Date: 2026-09-13

Adds the user-only account foundation:
- users.username (unique, DB-enforced) + users.account_type
- owner_user_id on every owner-scoped table, backfilled from created_by
  (media_files via the parent event, enforcement_policies /
  response_executions via the owning organization's owner)
- organization_id on enforcement_policies becomes nullable so personal
  workspaces can own policies directly (organization_id = NULL)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_user_foundation"
down_revision: Union[str, Sequence[str], None] = "1284c90c101c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = "cyberguard"

# owner_user_id backfill source per table (NULL elsewhere, covered by the
# org-owner / parent-event backfills below).
BACKFILL_COLUMNS = {
    "events": "created_by",
    "alerts": "created_by",
    "incidents": "created_by",
    "action_executions": "triggered_by_id",
    "audit_logs": "user_id",
}
OWNER_TABLES = list(BACKFILL_COLUMNS) + [
    "media_files",
    "enforcement_policies",
    "response_executions",
]


def upgrade() -> None:
    # --- users: username + account_type ---
    op.add_column("users", sa.Column("username", sa.String(length=64), nullable=True), schema=SCHEMA)
    op.add_column("users", sa.Column("account_type", sa.String(length=16), nullable=False, server_default="user"), schema=SCHEMA)
    op.create_index(op.f("ix_cyberguard_users_username"), "users", ["username"], unique=True, schema=SCHEMA)

    # --- owner_user_id columns ---
    for table in OWNER_TABLES:
        op.add_column(table, sa.Column("owner_user_id", sa.String(length=64), nullable=True), schema=SCHEMA)
        op.create_index(
            op.f(f"ix_cyberguard_{table}_owner_user_id"),
            table,
            ["owner_user_id"],
            unique=False,
            schema=SCHEMA,
        )

    # --- backfill owner_user_id from the table's creator column ---
    for table, col in BACKFILL_COLUMNS.items():
        op.execute(f"UPDATE {SCHEMA}.{table} SET owner_user_id = {col} WHERE {col} IS NOT NULL")

    # media_files: owner flows from the parent event's creator
    op.execute(
        f"UPDATE {SCHEMA}.media_files mf SET owner_user_id = e.created_by "
        f"FROM {SCHEMA}.events e WHERE e.id = mf.event_id AND e.created_by IS NOT NULL"
    )
    # enforcement_policies / response_executions: owner is the organization owner
    op.execute(
        f"UPDATE {SCHEMA}.enforcement_policies ep SET owner_user_id = o.owner_id "
        f"FROM {SCHEMA}.organizations o WHERE o.id = ep.organization_id"
    )
    op.execute(
        f"UPDATE {SCHEMA}.response_executions re SET owner_user_id = o.owner_id "
        f"FROM {SCHEMA}.organizations o WHERE o.id = re.organization_id"
    )

    # --- personal workspaces own policies/executions directly ---
    op.alter_column(
        "enforcement_policies",
        "organization_id",
        existing_type=sa.String(length=36),
        nullable=True,
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.alter_column(
        "enforcement_policies",
        "organization_id",
        existing_type=sa.String(length=36),
        nullable=False,
        schema=SCHEMA,
    )

    for table in reversed(OWNER_TABLES):
        op.drop_index(op.f(f"ix_cyberguard_{table}_owner_user_id"), table_name=table, schema=SCHEMA)
        op.drop_column(table, "owner_user_id", schema=SCHEMA)

    op.drop_index(op.f("ix_cyberguard_users_username"), table_name="users", schema=SCHEMA)
    op.drop_column("users", "account_type", schema=SCHEMA)
    op.drop_column("users", "username", schema=SCHEMA)
