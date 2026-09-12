# Schema Cutover — `cyberguard` (Phase -1)

This document records the one-time cutover from the legacy `public` schema to
the dedicated, RLS-enforced `cyberguard` schema. **All steps below were
executed against the production Supabase project on 2026-09-13.**

Preconditions:
- Backend venv with `alembic` installed (`cd backend && uv sync`).
- `.env` contains the service/postgres DSN (Supabase → Project Settings →
  Database → Connection string, direct connection — not the pooler).

---

## 1. Drop the disposable `public` tables

The pre-phase `public` tables held hackathon/test data and were explicitly
disposable. Only the 15 application tables were dropped; `auth`, `storage`,
`realtime`, `extensions`, and `vault` schemas were untouched.

```sql
DROP TABLE IF EXISTS public.users CASCADE;
DROP TABLE IF EXISTS public.organizations CASCADE;
DROP TABLE IF EXISTS public.organization_members CASCADE;
DROP TABLE IF EXISTS public.events CASCADE;
DROP TABLE IF EXISTS public.media_files CASCADE;
DROP TABLE IF EXISTS public.alerts CASCADE;
DROP TABLE IF EXISTS public.recommended_actions CASCADE;
DROP TABLE IF EXISTS public.incidents CASCADE;
DROP TABLE IF EXISTS public.incident_alerts CASCADE;
DROP TABLE IF EXISTS public.incident_events CASCADE;
DROP TABLE IF EXISTS public.response_catalog CASCADE;
DROP TABLE IF EXISTS public.response_executions CASCADE;
DROP TABLE IF EXISTS public.audit_logs CASCADE;
DROP TABLE IF EXISTS public.enforcement_policies CASCADE;
DROP TABLE IF EXISTS public.action_executions CASCADE;
```

## 2. Create the non-bypass application role

The backend connects as `cyberguard_api` (`NOBYPASSRLS`): every query it runs
is subject to row-level security. Migration `0003_rls` creates the role
automatically if it does not exist (as `NOLOGIN`), so the cutover only needs
to enable login and set a password:

```sql
ALTER ROLE cyberguard_api WITH LOGIN PASSWORD '<generated-strong-password>';
```

Grants (also applied by migration `0003_rls`; repeated here for reference):

```sql
GRANT USAGE ON SCHEMA cyberguard TO cyberguard_api, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_api;
GRANT ALL ON ALL SEQUENCES IN SCHEMA cyberguard TO cyberguard_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA cyberguard GRANT ALL ON TABLES TO cyberguard_api;
```

## 3. Run the migrations

```bash
cd backend
export MIGRATION_DATABASE_URL="postgresql+asyncpg://postgres:<password>@db.<ref>.supabase.co:5432/postgres"
uv run alembic upgrade head
```

Migration chain:
- `1284c90c101c_baseline` — `CREATE SCHEMA cyberguard` + all 15 tables.
- `0002_user_foundation` — `users.username` (unique) + `account_type`;
  `owner_user_id` on all owner-scoped tables with backfills;
  `enforcement_policies.organization_id` made nullable.
- `0003_rls` — RLS enabled on every table + owner-scoped / shared-read policies.

Verified round-trip (executed against the live DB after cutover):

```
uv run alembic upgrade head     # -> 0003_rls
uv run alembic downgrade -1     # 0003_rls -> 0002_user_foundation
uv run alembic upgrade head     # -> 0003_rls
```

## 4. Environment variables

`backend/.env` after cutover:

```env
# Application role — NOBYPASSRLS; all queries are RLS-scoped by app.user_id
DATABASE_URL=postgresql+asyncpg://cyberguard_api:<password>@db.<ref>.supabase.co:5432/postgres
# Service/postgres role — Alembic migrations + RLS verification only
MIGRATION_DATABASE_URL=postgresql+asyncpg://postgres:<password>@db.<ref>.supabase.co:5432/postgres
```

## 5. Verification performed

- `scripts/test_rls_pg.py` against the live project:
  user A sees exactly its own row, user B sees 0 rows, an unauthenticated
  (empty GUC) session sees 0 rows, and the service role sees the row.
- Application smoke path as `cyberguard_api` under RLS: `init_db()` seeded
  the response catalog (10 rows) and an authenticated user insert/select
  cycle succeeded via the `app.user_id` GUC.
- Final state: 15 tables in `cyberguard`, 15 RLS-enabled, 56 policies,
  full grants for `cyberguard_api`.

## Deferred

- **Supabase Realtime publication** for the `cyberguard` schema is deferred
  to the dashboard phase (add `cyberguard` tables to the `supabase_realtime`
  publication then).
