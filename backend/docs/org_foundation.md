# ORG-1 — Organization Foundation

Architecture reference for the org-side foundation: organization creation with
name salting, header-based API keys, the org-scoped gateway, and role-based
access (admin / analyst / viewer). User-mode code (Phases -1 through 7) is
untouched; the frozen `/organizations` router still answers 501 while
`ORG_ENABLED=false`.

## Components

| Layer | File | Purpose |
| --- | --- | --- |
| Migration | `alembic/versions/0008_org_foundation.py` | `organizations.display_name`/`status` columns, `organization_api_keys`, `organization_settings`, org-aware RLS |
| Models | `app/db/models.py` | `Organization` (+`display_name`, `status`), `OrganizationAPIKey`, `OrganizationSetting` |
| Org routes | `app/api/routes_orgs.py` | `/orgs` (creation, keys, settings, members) + `/org/{org_id}/gateway` |
| API keys | `app/services/api_key_service.py` | generation, SHA-256 hashing, validation, revocation, `get_org_from_api_key` dependency |
| RBAC | `app/core/permissions.py` | `OrgRole`, hierarchy, `require_org_role`, sensitive-setting keys |
| Tests | `scripts/test_org_foundation.py` | Suite 17 (wired into `run_all_tests.py`) |

## Data model

- **organizations** — `name` holds the *salted* unique name
  (`"Acme Corp-2"`), `display_name` the original, `status` is
  `active | suspended`. The pre-existing `owner_id` column is the org creator
  (the mission's `created_by`); it was kept under its historical name because
  frozen user-mode code (`get_tenant_context`, personal-workspace bootstrap)
  references it. `slug` remains the DB-level unique key.
- **organization_api_keys** — `key_hash` (SHA-256 hex, unique),
  `key_prefix` (first 16 chars for display), `last_used_at`, `expires_at`
  (NULL = never), `status` (`active | revoked`). Plaintext keys are returned
  exactly once by `POST /orgs/{org_id}/api-keys` and never stored.
- **organization_settings** — JSONB key/value per org;
  unique `(organization_id, key)`.
- **organization_members** — unchanged columns; policies widened (below).

## Name salting

`POST /orgs` salts on conflict: `"Acme Corp"` → `"Acme Corp-2"` → `-3`…
Uniqueness is enforced in the application loop rather than by a DB unique
constraint because every user's personal workspace legitimately shares the
literal name `"Personal Workspace"`. Applies to both email/password and OAuth
signup flows — the frontend calls the same endpoint after account creation
when the user selects "Organization" (`frontend/src/pages/OrganizationCreate.tsx`).

## API keys & gateway

- Keys look like `cg_live_<43 url-safe chars>` (~256 bits of entropy).
- **Hashing:** SHA-256, not bcrypt/argon2 — the key is a random secret with
  no entropy to brute-force, and validation must be an indexed exact-match
  lookup. Also keeps the "no new dependencies" rule.
- **Header:** server-to-server requests send `org_authorization: <key>`.
- **Gateway:** `POST /api/v1/org/{org_id}/gateway` with
  `{"action": "scan_email" | "scan_url" | "ingest_log", "data": {...}}`.
  `scan_email` / `scan_url` run the full production pipeline (heuristic +
  ML blend + XAI explanation) and persist Event + Alert scoped to the org;
  `ingest_log` persists the raw log event (detector-driven live analysis
  ships with ORG-2).
- Auth failures: missing/invalid/expired/revoked key → **401**; a valid key
  used against a different `org_id` → **403**; unknown action → **400**.

## Roles

`admin` (org creator; manages keys, members, settings) > `analyst` (runs
analyses, reads settings) > `viewer` (read-only; blocked from sensitive
settings keys `api_keys` and `billing`). `require_org_role(minimum)` resolves
membership against the `org_id` **path parameter**, so permissions are always
checked against the organization actually being addressed. Admins cannot
remove themselves; the owner cannot be removed or demoted.

## RLS (migration 0008)

All org predicates go through `cyberguard.org_member_role(org, user)` — a
`SECURITY DEFINER` function (owner fallback: the org creator is definitionally
an admin, which also makes policy checks robust to flush ordering with
`autoflush=False`). Querying `organization_members` directly from its own
policy recurses infinitely; the function breaks the cycle.

| Table | SELECT | WRITE |
| --- | --- | --- |
| `organization_api_keys` | permissive for the app role — hash validation runs *before* any identity is known (hashes/plaintext never returned by any API) | admin of the owning org |
| `organization_settings` | member; viewers blocked from sensitive keys | admin |
| `organization_members` | own row OR roster of own orgs | admin of the org (self-row insert preserved) |
| `enforcement_policies` | owner OR org member | owner OR org admin (personal rows unaffected: `organization_id` NULL never matches the org branch) |

Documented deviations from the mission's RLS sketch:

- `organizations` keeps the baseline app-role policy: tightening it to
  membership would break personal-workspace bootstrap and the startup
  policy seeder; membership enforcement happens at the API layer, and the
  org tables above carry real RLS isolation (Suite 17 asserts cross-org
  reads/writes are denied under the app role).
- Org events/alerts written by the gateway carry
  `owner_user_id = org.owner_id` and run under the owner's RLS identity
  (stamped by `validate_api_key`), so the existing owner-scoped policies
  apply unchanged. Member-readable org data views land with ORG-2.

## Test-suite RLS compatibility (Suite fixes)

The full regression suite predates the RLS-everything baseline and provisioned
rows via direct sessions with no `app.user_id` GUC; it has been red since the
schema cutover. Fixes (test-harness only, no behavior change to user-mode
product code):

- `scripts/_rls.py` — shared helpers: `as_user(user_id)` (GUC context) and
  `create_user_admin(...)` (service-role user provisioning).
- Suite 2, 5–16 mocks now stamp the GUC exactly where production
  `get_current_user` does; direct-session fixtures wrap blocks in `as_user`
  or provision through the service role.
- `_personal_tenant` overrides must be **async** dependencies — sync ones run
  in a worker thread whose context copy never propagates the `ContextVar`.
- Product bug fixes required by RLS: `_run_integration_pipeline`
  (routes_integrations) and `action_executor.execute` now propagate
  `owner_user_id` from the tenant/alert; `_seed_default_policies` runs
  through the service role (startup is a system task with no user identity).

## Frontend

- `/org/create` — `OrganizationCreate.tsx`: name form → salted creation →
  redirect to the org dashboard.
- `/org/:orgId/settings` — `OrganizationSettings.tsx` (admin-only surface):
  API key lifecycle (list prefix-only, create with optional expiry,
  plaintext shown once with copy + warning, revoke) and members (invite by
  email with role, change role, remove).
- `/org/:orgId/dashboard` — `OrganizationDashboard.tsx`: module grid
  (Phishing, URL, Deepfake, Impersonation, Live Log Analysis; Account
  Takeover disabled "Coming Soon") plus a copyable gateway `curl` example.
  No manual paste-boxes: org data arrives via gateway payloads and (later)
  mail-server streams. Nav integration and live org-scoped detector views
  land with ORG-2.
