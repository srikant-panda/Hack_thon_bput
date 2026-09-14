"""ORG-1 foundation: org display_name/status columns, API keys, org settings, RLS.

Revision ID: 0008_org_foundation
Revises: 0001_cyberguard_baseline
Create Date: 2026-09-14

Idempotent and error-tolerant, in the same spirit as the baseline:

1. ``organizations`` gains ``display_name`` (original name) and ``status``
   (``active`` | ``suspended``); the pre-existing ``owner_id`` column is the
   org creator (mission's ``created_by``) and stays as-is so the frozen
   user-mode code paths keep working untouched.
2. New tables ``organization_api_keys`` and ``organization_settings`` are
   created from the live SQLAlchemy metadata with ``checkfirst=True``.
3. RLS is enabled on both new tables:
   - ``organization_api_keys``: SELECT is permissive for the app role because
     hash-based key validation runs BEFORE any org/user identity is known
     (the plaintext/hashes are never returned by any API); writes require the
     caller to be an admin member of the owning org.
   - ``organization_settings``: reads require membership (analysts and admins
     see everything, viewers are blocked from sensitive keys); writes require
     admin membership.
4. ``organization_members`` policies are widened from the baseline's
   self-row-only form: admins can insert/update/delete membership rows of
   their org (member management), and members can read the roster of orgs
   they belong to. Self-row access is preserved (user-mode parity).
5. ``enforcement_policies`` policies gain org-admin write and org-member read
   branches (OR'd with the personal owner predicates, which are unchanged —
   personal rows have organization_id NULL and never match the org branches).
   Without this, seeding an org's default policy violates RLS.
6. Grants re-issued defensively.

Downgrade removes only what this migration added.
"""
import logging
from typing import Sequence, Union

from alembic import op

revision: str = "0008_org_foundation"
down_revision: Union[str, Sequence[str], None] = "0001_cyberguard_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_foundation")

SCHEMA = "cyberguard"

# Keys hidden from viewers at the API and RLS layer.
SENSITIVE_KEYS_SQL = "('api_keys', 'billing')"

# All org predicates go through this SECURITY DEFINER function: querying
# organization_members directly from its own policies (or from predicates that
# run while it is being scanned) triggers PostgreSQL's "infinite recursion
# detected in policy" — the definer function bypasses RLS and breaks the cycle.
_GUC = "current_setting('app.user_id', true)::text"


def _member_role_call(tbl: str) -> str:
    return f"cyberguard.org_member_role({tbl}.organization_id, {_GUC})"


def _admin_member_exists(tbl: str) -> str:
    return f"{_member_role_call(tbl)} = 'admin'"


def _member_exists(tbl: str) -> str:
    return f"{_member_role_call(tbl)} IS NOT NULL"


_SELF_ROW = f"user_id = {_GUC}"


def _ensure_membership_function() -> None:
    op.execute(
        f"""
        create or replace function {SCHEMA}.org_member_role(p_org text, p_user text)
        returns text
        language sql
        stable
        security definer
        set search_path = {SCHEMA}, pg_temp
        as $$
            select coalesce(
                (select m.role
                 from {SCHEMA}.organization_members m
                 where m.organization_id = p_org
                   and m.user_id = p_user
                 limit 1),
                -- The org creator is definitionally an admin. This fallback
                -- also makes policy checks robust to flush ordering within a
                -- transaction (autoflush=False may emit child inserts before
                -- the membership row exists).
                (select 'admin'
                 where exists (
                     select 1 from {SCHEMA}.organizations o
                     where o.id = p_org and o.owner_id = p_user))
            )
        $$;
        """
    )
    op.execute(f"revoke all on function {SCHEMA}.org_member_role(text, text) from public")
    op.execute(f"grant execute on function {SCHEMA}.org_member_role(text, text) to cyberguard_api")


def _add_column_if_missing(table: str, column_ddl: str, column_name: str) -> None:
    op.execute(
        f"ALTER TABLE {SCHEMA}.{table} ADD COLUMN IF NOT EXISTS {column_ddl}"
    )
    logger.info("ensured column %s.%s", table, column_name)


def _create_org_tables() -> None:
    import app.db.models  # noqa: F401 - populate Base.metadata
    from app.db.base import Base

    bind = op.get_bind()
    names = {"organization_api_keys", "organization_settings"}
    tables = [t for t in Base.metadata.sorted_tables if t.name in names]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)


def _enable_rls(table: str) -> None:
    op.execute(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")


def _replace_policy(table: str, policy: str, ddl: str) -> None:
    op.execute(f"DROP POLICY IF EXISTS {policy} ON {SCHEMA}.{table}")
    op.execute(ddl)


def _policies() -> None:
    keys_tbl = "organization_api_keys"
    settings_tbl = "organization_settings"

    # --- organization_api_keys ---
    # SELECT permissive: hash validation runs before any identity is known.
    _replace_policy(
        "organization_api_keys",
        "organization_api_keys_app_select",
        f"CREATE POLICY organization_api_keys_app_select ON {SCHEMA}.{keys_tbl} "
        f"FOR SELECT TO cyberguard_api USING (true)",
    )
    # Writes require admin membership of the owning org.
    _replace_policy(
        "organization_api_keys",
        "organization_api_keys_admin_write",
        f"CREATE POLICY organization_api_keys_admin_write ON {SCHEMA}.{keys_tbl} "
        f"FOR ALL TO cyberguard_api "
        f"USING ({_admin_member_exists(keys_tbl)}) "
        f"WITH CHECK ({_admin_member_exists(keys_tbl)})",
    )

    # --- organization_settings ---
    # Members read; viewers are blocked from sensitive keys. Writes admin-only.
    _replace_policy(
        "organization_settings",
        "organization_settings_member_select",
        f"CREATE POLICY organization_settings_member_select ON {SCHEMA}.{settings_tbl} "
        f"FOR SELECT TO cyberguard_api USING ("
        f"{_member_exists(settings_tbl)} AND ("
        f"{_member_role_call(settings_tbl)} IN ('admin', 'analyst') "
        f"OR {settings_tbl}.key NOT IN {SENSITIVE_KEYS_SQL}))",
    )
    _replace_policy(
        "organization_settings",
        "organization_settings_admin_write",
        f"CREATE POLICY organization_settings_admin_write ON {SCHEMA}.{settings_tbl} "
        f"FOR ALL TO cyberguard_api "
        f"USING ({_admin_member_exists(settings_tbl)}) "
        f"WITH CHECK ({_admin_member_exists(settings_tbl)})",
    )


def _grants() -> None:
    op.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA {SCHEMA} TO cyberguard_api")
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON TABLES TO cyberguard_api"
    )


def _member_policies() -> None:
    """Widen organization_members policies: admins manage, members read the
    roster, self-row access preserved (replaces the baseline self-row-only set).
    Predicates use the SECURITY DEFINER org_member_role() — a direct EXISTS on
    organization_members from its own policy recurses infinitely."""
    tbl = f"{SCHEMA}.organization_members"
    member_pred = _member_exists("organization_members")
    admin_pred = _admin_member_exists("organization_members")

    _replace_policy(
        "organization_members",
        "organization_members_select",
        f"CREATE POLICY organization_members_select ON {tbl} FOR SELECT TO cyberguard_api "
        f"USING ({_SELF_ROW} OR {member_pred})",
    )
    _replace_policy(
        "organization_members",
        "organization_members_insert",
        f"CREATE POLICY organization_members_insert ON {tbl} FOR INSERT TO cyberguard_api "
        f"WITH CHECK ({_SELF_ROW} OR {admin_pred})",
    )
    _replace_policy(
        "organization_members",
        "organization_members_update",
        f"CREATE POLICY organization_members_update ON {tbl} FOR UPDATE TO cyberguard_api "
        f"USING ({admin_pred}) WITH CHECK ({admin_pred})",
    )
    _replace_policy(
        "organization_members",
        "organization_members_delete",
        f"CREATE POLICY organization_members_delete ON {tbl} FOR DELETE TO cyberguard_api "
        f"USING ({_SELF_ROW} OR {admin_pred})",
    )


def _enforcement_policy_policies() -> None:
    """Widen enforcement_policies: org admins manage org policies, members
    read them. Personal (organization_id IS NULL) rows keep the exact
    baseline owner predicates — the org branches can never match them."""
    tbl = f"{SCHEMA}.enforcement_policies"
    member_pred = _member_exists("enforcement_policies")
    admin_pred = _admin_member_exists("enforcement_policies")
    owner_pred = "owner_user_id = current_setting('app.user_id', true)::text"

    _replace_policy(
        "enforcement_policies",
        "enforcement_policies_select",
        f"CREATE POLICY enforcement_policies_select ON {tbl} FOR SELECT TO cyberguard_api "
        f"USING ({owner_pred} OR {member_pred})",
    )
    _replace_policy(
        "enforcement_policies",
        "enforcement_policies_insert",
        f"CREATE POLICY enforcement_policies_insert ON {tbl} FOR INSERT TO cyberguard_api "
        f"WITH CHECK ({owner_pred} OR {admin_pred})",
    )
    _replace_policy(
        "enforcement_policies",
        "enforcement_policies_update",
        f"CREATE POLICY enforcement_policies_update ON {tbl} FOR UPDATE TO cyberguard_api "
        f"USING ({owner_pred} OR {admin_pred}) WITH CHECK ({owner_pred} OR {admin_pred})",
    )
    _replace_policy(
        "enforcement_policies",
        "enforcement_policies_delete",
        f"CREATE POLICY enforcement_policies_delete ON {tbl} FOR DELETE TO cyberguard_api "
        f"USING ({owner_pred} OR {admin_pred})",
    )


def upgrade() -> None:
    _add_column_if_missing("organizations", "display_name VARCHAR(255)", "display_name")
    _add_column_if_missing("organizations", "status VARCHAR(16) DEFAULT 'active'", "status")
    _create_org_tables()
    _enable_rls("organization_api_keys")
    _enable_rls("organization_settings")
    _ensure_membership_function()
    _member_policies()
    _enforcement_policy_policies()
    _policies()
    _grants()


def downgrade() -> None:
    op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.organization_settings CASCADE")
    op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.organization_api_keys CASCADE")
    op.execute(f"ALTER TABLE {SCHEMA}.organizations DROP COLUMN IF EXISTS display_name")
    op.execute(f"ALTER TABLE {SCHEMA}.organizations DROP COLUMN IF EXISTS status")
    # Restore the baseline self-row-only organization_members policies.
    tbl = f"{SCHEMA}.organization_members"
    for policy in (
        "organization_members_select",
        "organization_members_insert",
        "organization_members_update",
        "organization_members_delete",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {tbl}")
    op.execute(
        f"CREATE POLICY organization_members_select ON {tbl} FOR SELECT TO cyberguard_api "
        f"USING ({_SELF_ROW})"
    )
    op.execute(
        f"CREATE POLICY organization_members_insert ON {tbl} FOR INSERT TO cyberguard_api "
        f"WITH CHECK ({_SELF_ROW})"
    )
    op.execute(
        f"CREATE POLICY organization_members_update ON {tbl} FOR UPDATE TO cyberguard_api "
        f"USING ({_SELF_ROW}) WITH CHECK ({_SELF_ROW})"
    )
    op.execute(
        f"CREATE POLICY organization_members_delete ON {tbl} FOR DELETE TO cyberguard_api "
        f"USING ({_SELF_ROW})"
    )
