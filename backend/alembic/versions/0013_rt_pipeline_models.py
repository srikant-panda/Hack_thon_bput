"""RT-2: Real-time pipeline database models (gmail_accounts, job_queue, processed_emails).

Revision ID: 0013_rt_pipeline_models
Revises: 0012_tighten_realtime_policies
Create Date: 2026-09-16
"""

import logging
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0013_rt_pipeline_models"
down_revision: Union[str, Sequence[str], None] = "0012_tighten_realtime_policies"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.rt_pipeline_models")

SCHEMA = "cyberguard"

TABLES = ["scan_results", "gmail_accounts", "job_queue", "processed_emails"]


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    if is_pg:
        op.execute(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"')

        # 0. scan_results (support table for scan_result_id FK)
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {SCHEMA}.scan_results (
                id VARCHAR(36) PRIMARY KEY,
                owner_user_id VARCHAR(64) NOT NULL REFERENCES {SCHEMA}.users(id) ON DELETE CASCADE,
                provider_message_id VARCHAR(128) NOT NULL,
                verdict VARCHAR(32) NOT NULL DEFAULT 'safe',
                risk_score FLOAT NOT NULL DEFAULT 0.0,
                scan_details JSONB DEFAULT '{{}}'::jsonb,
                created_at TIMESTAMPTZ DEFAULT now()
            );
        """)
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_scan_results_owner_user_id ON {SCHEMA}.scan_results (owner_user_id);")

        # 1. gmail_accounts
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {SCHEMA}.gmail_accounts (
                id VARCHAR(36) PRIMARY KEY,
                owner_user_id VARCHAR(64) NOT NULL REFERENCES {SCHEMA}.users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                access_token_encrypted TEXT NULL,
                refresh_token_encrypted TEXT NOT NULL,
                last_history_id VARCHAR(128) NULL,
                watch_expiration TIMESTAMPTZ NULL,
                sync_status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (sync_status IN ('active', 'paused', 'error')),
                last_sync_at TIMESTAMPTZ NULL,
                last_error TEXT NULL,
                created_at TIMESTAMPTZ DEFAULT now(),
                updated_at TIMESTAMPTZ DEFAULT now(),
                CONSTRAINT uq_gmail_accounts_owner_email UNIQUE (owner_user_id, email)
            );
        """)
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_gmail_accounts_owner_user_id ON {SCHEMA}.gmail_accounts (owner_user_id);")

        # 2. job_queue
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {SCHEMA}.job_queue (
                id VARCHAR(36) PRIMARY KEY,
                owner_user_id VARCHAR(64) NOT NULL REFERENCES {SCHEMA}.users(id) ON DELETE CASCADE,
                job_type VARCHAR(32) NOT NULL CHECK (job_type IN ('gmail_sync', 'email_fetch', 'email_analysis', 'email_result')),
                job_id VARCHAR(255) NOT NULL UNIQUE,
                status VARCHAR(32) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'dead_letter')),
                retry_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 5,
                payload JSONB NOT NULL DEFAULT '{{}}'::jsonb,
                result JSONB NULL,
                error TEXT NULL,
                next_retry_at TIMESTAMPTZ NULL,
                created_at TIMESTAMPTZ DEFAULT now(),
                updated_at TIMESTAMPTZ DEFAULT now(),
                started_at TIMESTAMPTZ NULL,
                completed_at TIMESTAMPTZ NULL
            );
        """)
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_job_queue_owner_user_id ON {SCHEMA}.job_queue (owner_user_id);")
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_job_queue_job_id ON {SCHEMA}.job_queue (job_id);")

        # 3. processed_emails
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {SCHEMA}.processed_emails (
                id VARCHAR(36) PRIMARY KEY,
                owner_user_id VARCHAR(64) NOT NULL REFERENCES {SCHEMA}.users(id) ON DELETE CASCADE,
                gmail_account_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.gmail_accounts(id) ON DELETE CASCADE,
                gmail_message_id VARCHAR(128) NOT NULL,
                subject TEXT NULL,
                sender VARCHAR(255) NULL,
                received_at TIMESTAMPTZ NOT NULL,
                processing_status VARCHAR(32) NOT NULL DEFAULT 'received' CHECK (processing_status IN ('received', 'fetching', 'fetched', 'analyzing', 'analyzed', 'completed', 'failed')),
                risk_score FLOAT NULL,
                classification VARCHAR(32) NULL CHECK (classification IS NULL OR classification IN ('phishing', 'safe', 'suspicious')),
                signals JSONB NULL,
                scan_result_id VARCHAR(36) NULL REFERENCES {SCHEMA}.scan_results(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ DEFAULT now(),
                updated_at TIMESTAMPTZ DEFAULT now(),
                CONSTRAINT uq_processed_emails_owner_msg UNIQUE (owner_user_id, gmail_message_id)
            );
        """)
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_processed_emails_owner_user_id ON {SCHEMA}.processed_emails (owner_user_id);")
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_processed_emails_gmail_account_id ON {SCHEMA}.processed_emails (gmail_account_id);")

        # RLS and Policies
        for table in TABLES:
            q = f"{SCHEMA}.{table}"
            op.execute(f"ALTER TABLE {q} ENABLE ROW LEVEL SECURITY;")
            op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {q} TO cyberguard_api;")

            pred = f"owner_user_id = current_setting('app.user_id', true)::text"
            op.execute(f"DROP POLICY IF EXISTS {table}_select ON {q};")
            op.execute(f"DROP POLICY IF EXISTS {table}_insert ON {q};")
            op.execute(f"DROP POLICY IF EXISTS {table}_update ON {q};")
            op.execute(f"DROP POLICY IF EXISTS {table}_delete ON {q};")

            op.execute(f"CREATE POLICY {table}_select ON {q} FOR SELECT TO cyberguard_api USING ({pred});")
            op.execute(f"CREATE POLICY {table}_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({pred});")
            op.execute(f"CREATE POLICY {table}_update ON {q} FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred});")
            op.execute(f"CREATE POLICY {table}_delete ON {q} FOR DELETE TO cyberguard_api USING ({pred});")


def downgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    if is_pg:
        op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.processed_emails CASCADE;")
        op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.job_queue CASCADE;")
        op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.gmail_accounts CASCADE;")
        op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.scan_results CASCADE;")
