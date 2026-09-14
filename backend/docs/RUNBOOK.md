# CYBERGUARD Runbook — How to Start the App in Every Condition

This is the single source of truth for starting CYBERGUARD against any state
of the database — healthy, empty, freshly-wiped, or wrong-role. It reflects
the **from-scratch baseline migration** (`alembic/versions/0001_cyberguard_baseline.py`)
and the self-healing bootstrap in `app/db/session.py` + `alembic/env.py`.

---

## 0. The mental model (read this once)

There are **two database roles** and **three layers of schema creation**:

| Layer | Role | What it does |
|---|---|---|
| App runtime (`uvicorn`) | `cyberguard_api` (NOBYPASSRLS, no CREATE priv) | `init_db()` → best-effort `CREATE SCHEMA IF NOT EXISTS cyberguard` (skipped silently if the role lacks CREATE), then `create_all()` from ORM metadata + seeds the response catalog |
| Migrations (`alembic`) | `postgres` (MIGRATION_DATABASE_URL) | `env.py` ensures the schema exists, then `0001_cyberguard_baseline` creates **all tables from the live ORM metadata** (baseline + `0008_org_foundation`), installs roles, **RLS policies**, and grants |
| Google Supabase | — | Auth (JWTs), storage. The Postgres DB itself is a plain Postgres database |

**Rule of thumb:** the app can heal *tables* by itself; only alembic can heal
*schema + RLS*. If the schema was wiped, run alembic (section 3).

Key facts you will need:

- Backend venv & commands always run from `backend/` with `uv run …`.
- `DATABASE_URL` (app, role `cyberguard_api`) and `MIGRATION_DATABASE_URL`
  (migrations, role `postgres`) both live in `backend/.env`.
- The migration bookkeeping table is `public.alembic_version` (owned by
  `postgres`). If migrations were reset, drop it first (section 3).
- If a count query "returns 0" for a table you know has data, it is almost
  always **RLS**, not emptiness — `cyberguard_api` is NOBYPASSRLS and sees
  nothing without the `app.user_id` GUC. Verify with the `postgres` role.

Health check: `curl http://127.0.0.1:8000/api/v1/health` →
`{"status":"ok","database_connected":true,...}`.
(`supabase_connected:false` refers to Storage and does not block the API.)

---

## 1. Normal start (everything already set up)

```bash
# Terminal 1 — backend (from repo root)
cd backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2 — frontend (from repo root)
cd frontend
npm run dev          # → http://localhost:5173
```

Verify:

```bash
curl http://127.0.0.1:8000/api/v1/health          # database_connected: true
curl -s -o /dev/null -w "%{http_code}" http://localhost:5173/   # 200
```

---

## 2. First-time setup (fresh clone)

```bash
cd backend
uv sync                        # create .venv from uv.lock
cp .env.example .env           # then fill in DATABASE_URL / MIGRATION_DATABASE_URL /
                               # SUPABASE_* / GOOGLE_GMAIL_* / LLM keys
uv run alembic upgrade head    # schema + all tables (incl. 0008 org tables) + RLS + grants + roles
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000

cd ../frontend
npm install
npm run dev
```

On first boot the app seeds `cyberguard.response_catalog` (10 actions) and a
default enforcement policy per organization (no-op when no orgs exist).

---

## 3. Schema was deleted / wiped (the incident)

**Symptoms:** `relation "cyberguard.users" does not exist`, or
`permission denied for database postgres` in the startup log, or every table
missing. The app's `init_db()` will rebuild *tables* automatically — but only
if the *schema* exists or the connecting role can create it. The app role
cannot create schemas, so do:

```bash
cd backend
uv run alembic upgrade head
```

That's it. The baseline migration is error-tolerant and idempotent:

1. `CREATE SCHEMA IF NOT EXISTS "cyberguard"` — schema recreated automatically.
2. All tables created from the live SQLAlchemy models (`checkfirst=True`,
   so partially-existing tables never fail).
3. Roles `cyberguard_api` / `authenticated` created only when missing.
4. RLS enabled on all tables + owner-scoped policies keyed on `app.user_id`.
5. Grants re-issued defensively.

Then restart the backend (section 1).

### If `alembic upgrade head` itself fails

| Error | Meaning | Fix |
|---|---|---|
| `must be owner of table alembic_version` | you ran alembic with the app role, or a stale bookkeeping table exists owned by another role | run migrations with `MIGRATION_DATABASE_URL` (role `postgres`); `DROP TABLE IF EXISTS public.alembic_version` as that role |
| `permission denied for database postgres` | connecting as `cyberguard_api` (app role) | point `alembic` at `MIGRATION_DATABASE_URL` |
| `role "cyberguard_api" does not exist` | fresh Supabase project | not an error — the baseline creates it |
| `can't adapt …` / connection refused | Supabase paused or URL typo | check `MIGRATION_DATABASE_URL`, revive the project in the Supabase dashboard |

---

## 4. Full reset from scratch (delete everything, rebuild)

**Destroys all data.** Use the dedicated drop script
(`backend/scripts/drop_cyberguard_schema.py`) — it deletes all RLS
policies, all tables, the schema itself, and the migration bookkeeping,
with a dry-run plan, role-ownership guards and a typed confirmation:

```bash
cd backend
uv run python scripts/drop_cyberguard_schema.py --dry-run   # see exactly what goes
uv run python scripts/drop_cyberguard_schema.py --yes       # actually drop it

# Rebuild everything from the single baseline, then start (section 1);
# first boot re-seeds the response catalog.
uv run alembic upgrade head
```

Expected result: `alembic current` → `0001_cyberguard_baseline (head)`;
26 tables in `cyberguard` (24 baseline + 2 ORG-1 org tables), all with `rowsecurity = true`, 96 policies (as of migration `0008_org_foundation`).

Safety behaviour of the drop script:

- connects with `MIGRATION_DATABASE_URL` (role `postgres`) and **refuses to
  run** as the app role (`cyberguard_api`) or a non-owner of the schema;
- `--dry-run` prints every table and its policy count without deleting;
- without `--yes` it demands the typed phrase `DROP cyberguard`;
- prints a post-state verification line when finished.

---

## 5. Local-only mode without Supabase (SQLite)

`app/db/session.py` builds a `sqlite+aiosqlite` engine when `DATABASE_URL`
is a SQLite URL and translates the `cyberguard` schema away automatically
(`schema_translate_map`). RLS is a Postgres feature — SQLite runs without it
(fine for local checks and the test suite).

```bash
cd backend
# .env: DATABASE_URL=sqlite+aiosqlite:///./cyberguard.db
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

`init_db()` creates all tables + seeds on first boot; no alembic needed.

---

## 6. Demo / mock mode (frontend only, no backend at all)

`frontend/.env.local`: set `VITE_USE_MOCK` to anything other than `'false'`
(or delete the key). The frontend runs entirely on the in-browser mock API —
enforcement actions are disabled and labelled "DEMO MODE". This is the
hackathon-demo safe path; it never touches the real database.

For the real stack: `VITE_USE_MOCK=false` + `VITE_API_BASE_URL=http://127.0.0.1:8000`.

---

## 7. Tests / evaluation harness

```bash
cd backend
uv run pytest tests/ -q          # full suite (20 tests, ~95s)
uv run pytest tests/test_eval_url.py -v      # single engine eval
uv run pytest tests/ -q --offline            # no network fetches (cached data only)
```

The suite runs against SQLite (RLS not exercised there). Frontend has no unit
test runner — verify with `npx tsc --noEmit` (typecheck) and a manual pass
against the running stack.

---

## 8. Retraining the URL model (v3 / v3.1)

```bash
cd backend
uv run python ml/scripts/train_url_v3.py        # v3  → ml/models/url_xgb_v3.pkl
uv run python ml/scripts/train_url_v3.py v3.1   # v3.1 → ml/models/url_xgb_v3.1.pkl
```

Downloads the real phishing feed once (~60 MB, cached in `ml/data/cache/`,
gitignored). Switch the served model via `ml/models/calibration.json`
→ `url_model_version` (`v3.1` | `v3` | `v2`); the loader falls back
gracefully when an artifact is missing.

---

## 9. Troubleshooting quick reference

| Symptom | Cause | Action |
|---|---|---|
| `database_connected: false` in /health | DB down / URL wrong / schema missing | follow section 3 |
| App role queries return 0 rows unexpectedly | RLS deny-all without `app.user_id` GUC | expected behaviour; verify with `postgres` role |
| Startup log: `lacks CREATE privilege — skipping schema bootstrap` | app role cannot create schemas (by design) | run `uv run alembic upgrade head` once |
| `supabase_connected: false` | Storage bucket/key issue | check `SUPABASE_*` keys; API still works |
| Frontend blank / CORS errors | backend not on `VITE_API_BASE_URL` | start backend, check `CORS_ORIGINS` in backend/.env |
| Port already in use | stale server | `kill $(lsof -t -i:8000)` / `-i:5173` |
