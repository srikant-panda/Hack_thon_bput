"""ORG-5: tighten realtime reader policies (absorbs the ORG-2 demo tradeoff).

Revision ID: 0012_tighten_realtime_policies
Revises: 0011_org_email_groups
Create Date: 2026-09-15

Migration 0009 added permissive ``FOR SELECT TO authenticated USING (true)``
policies on ``cyberguard.org_log_events`` and ``cyberguard.alerts`` so the
Supabase Realtime subscriber role could stream org rows. This migration
replaces them with membership-gated policies:

- ``org_log_events``: the calling Supabase user (``auth.uid()``) must be a
  member of the owning organization — evaluated through the ORG-1
  ``SECURITY DEFINER`` ``cyberguard.org_member_role()`` function (keyed on
  text user ids, so ``auth.uid()`` is cast).
- ``alerts``: org rows require membership; personal rows (organization_id
  IS NULL) require owner_user_id = auth.uid() — WALRUS-style owner access.

Guards:
- SQLite / vanilla Postgres (no ``auth`` schema / no ``auth.uid()``): the
  permissive policies are still dropped and the gated creation is skipped —
  a clean no-op for the tightening itself.
- The Supabase Realtime subscriber role keeps working: it now only streams
  rows the calling user is entitled to.

User-plane policies from the 0008-era baseline (owner-scoped, TO
cyberguard_api) are untouched.
"""

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0012_tighten_realtime_policies"
down_revision: Union[str, Sequence[str], None] = "0011_org_email_groups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.tighten_realtime")

SCHEMA = "cyberguard"

PERMISSIVE_POLICIES = (
    ("org_log_events", "org_log_events_authenticated_select"),
    ("alerts", "alerts_authenticated_select"),
)

GATED_POLICIES = {
    "org_log_events": f"""
        CREATE POLICY org_log_events_realtime_select ON {SCHEMA}.org_log_events
        FOR SELECT TO authenticated
        USING (
            cyberguard.org_member_role(
                org_log_events.organization_id,
                auth.uid()::text
            ) IS NOT NULL
        )
    """,
    "alerts": f"""
        CREATE POLICY alerts_realtime_select ON {SCHEMA}.alerts
        FOR SELECT TO authenticated
        USING (
            (alerts.organization_id IS NOT NULL
             AND cyberguard.org_member_role(alerts.organization_id, auth.uid()::text) IS NOT NULL)
            OR
            (alerts.organization_id IS NULL AND alerts.owner_user_id = auth.uid()::text)
        )
    """,
}


def _has_auth_uid() -> bool:
    """True when the auth schema and auth.uid() exist (Supabase)."""
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return False
    return (
        bind.execute(
            text("select to_regprocedure('auth.uid()') is not null")
        ).scalar()
    )


def upgrade() -> None:
    bind = op.get_bind()
    # 1. Drop the ORG-2 permissive policies everywhere (safe on all backends).
    for table, policy in PERMISSIVE_POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {SCHEMA}.{table}")
        logger.info("dropped permissive policy %s on %s", policy, table)

    # 2. Install gated policies only where auth.uid() exists.
    if not _has_auth_uid():
        logger.info(
            "no auth.uid() (vanilla Postgres / SQLite) — gated realtime policies skipped; "
            "realtime subscription simply returns no rows for 'authenticated'"
        )
        return

    for table, ddl in GATED_POLICIES.items():
        gated_policy_name = "org_log_events_realtime_select" if table == "org_log_events" else "alerts_realtime_select"
        op.execute(f"DROP POLICY IF EXISTS {gated_policy_name} ON {SCHEMA}.{table}")
        op.execute(text(ddl))
        logger.info("created gated realtime policy on %s", table)


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS org_log_events_realtime_select ON {SCHEMA}.org_log_events")
    op.execute(f"DROP POLICY IF EXISTS alerts_realtime_select ON {SCHEMA}.alerts")
    # Restore the ORG-2 permissive state verbatim.
    op.execute(
        f"CREATE POLICY org_log_events_authenticated_select ON {SCHEMA}.org_log_events "
        f"FOR SELECT TO authenticated USING (true)"
    )
    op.execute(
        f"CREATE POLICY alerts_authenticated_select ON {SCHEMA}.alerts "
        f"FOR SELECT TO authenticated USING (true)"
    )
