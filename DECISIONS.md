# DECISIONS

Append-only decision log. Each entry: date, decision, rationale, and
consequences. Newest entries at the bottom.

---

- **Decision.** Hybrid blending is monotonic: ML can raise but never lower a heuristic score (safety property).

- **2026-09-13 — Dedicated `cyberguard` schema + PostgreSQL RLS as the isolation backbone (Phase -1).**
  All application tables moved out of `public` into a dedicated `cyberguard`
  schema, managed by Alembic migrations (introduced this phase; previously
  schema existed only as `Base.metadata.create_all`). The backend connects as
  a dedicated `cyberguard_api` role with `NOBYPASSRLS`; row visibility is
  governed by the `app.user_id` / `request.role` GUCs (session-scoped
  `set_config`, applied per transaction by an `after_begin` event and reset on
  session release). Rationale: database-enforced isolation beneath the
  application filters, so a bug in a query filter cannot leak another user's
  data. Consequences: migrations are now the schema source of truth
  (`create_all` remains as checkfirst bootstrap for SQLite tests, which run
  schema-free via `schema_translate_map`); unauthenticated requests can read
  nothing from owner tables by construction.

- **2026-09-13 — Owner-scoped tenancy in the active path; organization features frozen, not removed (Phase -1).**
  Personal workspaces are the active product surface: every request resolves
  to `TenantContext{organization_id: None, owner_user_id: user.id, role:
  "admin"}` and all queries filter through `tenant_criteria(model, tenant)`.
  Organization tables, code paths, and the server-mode integration surface
  (`routes_integrations`, `enforcement_engine`, `action_executor`) are frozen
  behind `ORG_ENABLED=false` (501 "coming soon") and reactivate with the later
  Orgs Phase. Rationale: decouple, don't demolish — the user-only path must
  not depend on org membership. Consequences: rows created in personal mode
  carry `organization_id = NULL` plus `owner_user_id`; org-mode data written
  by integrations without `owner_user_id` stays invisible under RLS until the
  Orgs Phase revisits policies.

- **2026-09-13 — Deliberate extensions to the Phase -1 spec (documented deviations).**
  1. **GUC application is lazy (per transaction), not at session acquire.**
     `get_current_user` depends on `get_db`, so the session exists *before*
     the user is known; an acquire-time `set_config` would always see NULL.
     The `after_begin` event applies the GUC at the first execution of every
     transaction, which also covers the JIT user upsert that must itself pass
     the `users` RLS policy. `request.role='authenticated'` is set alongside
     so the app role can read the shared-read tables per spec.
  2. **Shared-read tables also carry an app-role policy** (`response_catalog`,
     `organizations`) — otherwise startup seeding of the response catalog and
     `/auth/me` break under RLS for `cyberguard_api`.
  3. **`response_executions` received `owner_user_id`** beyond the spec's
     column list — it is a first-class personal-workspace table and would
     otherwise be deny-all under RLS.
  4. **Child/join tables** (`recommended_actions`, `incident_alerts`,
     `incident_events`, `organization_members`) got EXISTS-on-parent /
     `user_id` policies — RLS-enabled tables without policies are deny-all.
  5. **`enforcement_policies.organization_id` made nullable** — personal
     workspaces own policies directly with `organization_id = NULL`.
  6. **Migration `0003_rls` creates missing roles** (`cyberguard_api`,
     `authenticated`) so the chain installs on vanilla PostgreSQL, not only
     Supabase; the cutover then only sets LOGIN/PASSWORD.
  7. **Frozen-org 501 uses a dedicated `ComingSoonError` handler** to emit the
     spec'd `{"detail": "Organization accounts are coming soon."}` envelope
     while leaving the global error shapes untouched.

- **2026-09-13 — Backend-mediated signup/sign-in with server-enforced usernames (Phase -1).**
  `POST /auth/signup` and `POST /auth/signin` now proxy Supabase Auth from the
  backend so `username` (`^[a-z0-9_.]{3,32}$`, DB-unique) can be enforced and
  resolved server-side (username → email lookup runs on the service-role
  engine, `app/db/admin.py`, because RLS denies anonymous reads of `users`).
  The frontend installs the returned session via `supabase.auth.setSession`,
  keeping the existing token-refresh flow intact. OAuth users get their
  project row (with an auto-generated unique username) via the JIT upsert in
  `get_current_user`. Rationale: username uniqueness across auth identities
  cannot be guaranteed client-side.

- **2026-09-13 — Gmail connector with own OAuth client, encrypted token vault, honest provider registry (Phase 1-2).**
  Gmail mailbox access uses a dedicated Google Cloud OAuth client owned by
  CYBERGUARD — deliberately separate from Supabase's Google identity provider,
  so login tokens can never be confused with mailbox tokens. Tokens are
  encrypted at rest (Fernet via `CONNECTOR_TOKEN_KEY`) and never leave the
  backend; the OAuth callback authenticates with a single-use expiring state
  row (consumed via the service-role helper) instead of a bearer token, and
  redirects carry only a safe status. The provider registry declares Gmail
  enabled (when configured) and Outlook/Yahoo/iCloud as coming-soon or
  unsupported with explicit reasons — no fake provider success anywhere.
  Rationale: mailbox access is the highest-sensitivity integration the
  platform has, so token custody, audit (`connector_operation_logs`), and
  honest capability reporting are foundational. Mailbox scanning is Phase 3;
  quarantine/sender actions Phase 4; event email notifications Phase 7.

- **2026-09-13 — Mailbox scanning is stateless, deterministic, and analysis-only (Phase 3).**
  Provider messages normalize into `NormalizedMessage` (Gmail MIME/base64url
  parsing lives in the adapter; engines never see provider formats). Scans run
  the existing heuristic + ML engines (phishing, URL, impersonation; media
  attachments are honestly skipped — no binary is downloaded yet) and aggregate
  with the shared `scoring_service` weights. Scan results are computed on
  request rather than persisted, so the reported verdict can always be
  reproduced from the message itself. Enforcement is reported as
  `provider_operation_status = "deferred_to_phase_4"` — the UI shows the
  recommendation and explicitly states nothing was done to the mailbox.
  Overall explanations are generated by deterministic rules (fast, stable, and
  auditable) instead of the LLM, which remains available for interactive use.

- **2026-09-13 — Enforcement executes real Gmail writes with a 5-minute asyncio expiry scheduler (Phase 4).**
  Quarantine is implemented with Gmail labels (`CYBERGUARD-Quarantine` added,
  `INBOX` removed) and release reverses it; sender blocking uses Gmail filters
  (`gmail.settings.basic` scope added to the OAuth consent — without
  re-consent the adapter surfaces `insufficient_scope` honestly). Per-user
  settings (expiry 3h/24h/custom/manual, permanent-delete toggle,
  auto-quarantine toggle) gate every action; nothing is simulated. The expiry
  scheduler is a hand-rolled asyncio loop (no apscheduler dependency) running
  on the service-role engine, and it fails safe: a provider error leaves the
  item quarantined/blocked with `last_error` recorded for retry next pass.
  Extensions to the spec's schema: `owner_user_id` denormalized on
  connector_settings/quarantined_items/blocked_senders (required for the RLS
  owner-policy pattern) and `last_error` columns for honest failure reporting.
  The Phase 3 deferral semantics remain only where enforcement is disabled or
  unnecessary — a successful action now reports `provider_operation_status =
  "success"` with the concrete Gmail operations performed.

- **2026-09-13 — Dual-write security history + audit with actor distinction; chat excluded from permanent history (Phase 5).**
  `record_event` writes one `security_events` row AND a matching `audit_logs`
  row with the same `actor_type` (user | system | scheduler), guaranteeing the
  two ledgers never disagree about who acted. Writers must pass the real
  provider operation outcome — history defaults are success-free by design.
  The review view (`/quarantine/{id}/review`) assembles the ordered event
  chain per message and computes available actions from live state (item
  status, connector readiness, permanent-delete setting) rather than offering
  static buttons. AI chat remains ephemeral: sessionStorage-only under a
  per-tab key, destroyed on tab close, and the assistant's audit entry now
  records the intent class only — chat content is never permanent history.
  Migration `0006` backfills `audit_logs.actor_type='user'`; the history
  backfill script is idempotent against pre-Phase-5 enforcement rows.

- **2026-09-13 — 14-method provider contract with capability gating, and DB-logged email notifications for demo reliability (Phase 6-7).**
  The `EmailProvider` contract was finalized to the Excalidraw 14 methods
  with a `capabilities` property exposing `supports_*` boolean flags; the
  enforcement engine and scheduler resolve providers through
  `get_provider(connector.provider)` and consult capabilities before acting
  (a provider without sender-rule support skips filter creation and says so).
  An in-memory `MockEmailProvider` with configurable failure flags proves the
  engine is Gmail-independent. Notifications deliberately use a DB-logged
  delivery backend as the default: the rendered email is persisted to
  `notification_logs` (status sent/failed, `backend=db_log`), making the demo
  deterministic with zero external dependency; optional SMTP is best-effort
  with automatic fallback. The recipient is always the user-registered
  `users.notification_email` — connected mailboxes are never used for system
  notifications (privacy/spam boundary). `backend` was added to the spec's
  notification_logs columns to record the actual delivery path.
