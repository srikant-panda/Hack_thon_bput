"""GMAIL-CONNECT-MANAGE: add status and disconnected_at to gmail_accounts.

Revision ID: 0022_gmail_account_status
Revises: 0021_events_realtime_publication
Create Date: 2026-09-22

Why
---
Supports Gmail connect/disconnect lifecycle:
- status VARCHAR(20) DEFAULT 'ACTIVE' NOT NULL
- disconnected_at TIMESTAMPTZ NULL
- refresh_token_encrypted altered to nullable so credentials can be purged on disconnect
"""
import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0022_gmail_account_status"
down_revision: Union[str, Sequence[str], None] = "0021_events_realtime_publication"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.gmail_status")

SCHEMA = "cyberguard"


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        # SQLite fallback for in-memory unit tests
        with op.batch_alter_table("gmail_accounts") as batch_op:
            batch_op.add_column(
                op.f("status"),
                type_=op.f("VARCHAR(20)"),
                server_default="ACTIVE",
            )
            batch_op.add_column(
                op.f("disconnected_at"),
                type_=op.f("TIMESTAMPTZ"),
                nullable=True,
            )
        return

    # Postgres migration
    # 1. Add status column if not exists
    bind.execute(
        text(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = '{SCHEMA}' 
                      AND table_name = 'gmail_accounts' 
                      AND column_name = 'status'
                ) THEN
                    ALTER TABLE {SCHEMA}.gmail_accounts 
                    ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';
                END IF;
            END $$;
            """
        )
    )

    # 2. Add disconnected_at column if not exists
    bind.execute(
        text(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = '{SCHEMA}' 
                      AND table_name = 'gmail_accounts' 
                      AND column_name = 'disconnected_at'
                ) THEN
                    ALTER TABLE {SCHEMA}.gmail_accounts 
                    ADD COLUMN disconnected_at TIMESTAMPTZ NULL;
                END IF;
            END $$;
            """
        )
    )

    # 3. Allow refresh_token_encrypted to be NULL on disconnect
    bind.execute(
        text(
            f"""
            ALTER TABLE {SCHEMA}.gmail_accounts 
            ALTER COLUMN refresh_token_encrypted DROP NOT NULL;
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("gmail_accounts") as batch_op:
            batch_op.drop_column("disconnected_at")
            batch_op.drop_column("status")
        return

    bind.execute(
        text(
            f"""
            ALTER TABLE {SCHEMA}.gmail_accounts 
            DROP COLUMN IF EXISTS disconnected_at;
            """
        )
    )
    bind.execute(
        text(
            f"""
            ALTER TABLE {SCHEMA}.gmail_accounts 
            DROP COLUMN IF EXISTS status;
            """
        )
    )
    bind.execute(
        text(
            f"""
            ALTER TABLE {SCHEMA}.gmail_accounts 
            ALTER COLUMN refresh_token_encrypted SET NOT NULL;
            """
        )
    )
