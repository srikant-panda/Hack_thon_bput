# ORG-3 — Org-Level Mail Server Connectors

Server-to-server infrastructure management for organization mail
(Google Workspace admin API, Microsoft 365 Graph, generic IMAP/SMTP).
Distinct from the Phase-2 personal Gmail OAuth connector — this is
"server management", not a personal mailbox. Built on ORG-1/2; user-mode
connectors (`app/services/email_providers/`, `connectors/`) are untouched.

## Components

| Layer | File | Purpose |
| --- | --- | --- |
| Migration | `alembic/versions/0010_org_mail_connectors.py` | 3 tables + org-scoped RLS |
| Models | `app/db/models.py` | `OrgMailServer`, `OrgMailServerSetting`, `OrgMailServerLog` |
| Connectors | `app/services/org_mail_connector_service.py` | base + Google/M365/IMAP adapters, pluggable transport, Fernet credentials |
| Routes | `app/api/routes_org_mail.py` | CRUD, connect/disconnect, fetch/quarantine, per-server logs & settings |
| Tests | `scripts/test_org_mail_connectors.py` | Suite 19 |

## Data model

- **org_mail_servers** — `name` (unique per org), `provider_type`
  (`google_workspace | microsoft_365 | imap_smtp`), `status`
  (`connected | disconnected | error`), `credentials_encrypted`
  (Fernet blob), `last_connected_at`, `last_error`.
- **org_mail_server_settings** — per-server key/value config, defaults
  seeded at creation: `scan_interval_seconds` (300), `quarantine_enabled`
  (true), `auto_block_malicious_senders` (false), `quarantine_expiry_hours` (24).
- **org_mail_server_logs** — per-server stream with
  `log_type` (`connection | scan | quarantine | error`), `message`,
  `metadata` (jsonb). **Logs are grouped BY server**: every query and UI
  surface filters by `mail_server_id`; streams are never merged.

## Credential handling

Credentials are provider-specific JSON blobs validated against
`CREDENTIAL_SCHEMAS` (Google: `service_account_key` + `delegated_user`;
M365: `client_id`/`client_secret`/`tenant_id`; IMAP: `host`/`port`/
`username`/`password`), then Fernet-encrypted with the shared
`CONNECTOR_TOKEN_KEY` (`app/core.crypto`). Plaintext never reaches the
database, logs, or API responses (`has_credentials` boolean only). A
CONNECTOR_TOKEN_KEY rotation makes stored blobs undecryptable — surfaced as
a validation error telling the admin to reconnect.

## Transport architecture (no new dependencies)

The connector classes are protocol adapters; wire calls go through a
pluggable transport registry (`ORG_MAIL_TRANSPORTS`). The shipped default is
`SimulationTransport`: it performs real credential validation and returns
clearly-flagged simulated results (`"simulated": true`, log metadata
`mode: simulated`) — the same honest-simulation pattern as
`action_executor`. The prompt named `google-api-python-client` / `msal` /
`imaplib`; the first two are third-party packages outside the frozen
dependency set, so they are NOT installed — dropping in the real drivers is
a transport registration (e.g. a `GoogleRealTransport.verify` doing the
domain-wide-delegation JWT exchange; `msal.ConfidentialClientApplication`
for Graph client-credentials; stdlib `imaplib` for IMAP) with zero changes
to the service, routes, or UI. Suite 19 demonstrates the seam by swapping in
a stub transport that yields 5 messages.

## Endpoints (all under `/api/v1/org/{org_id}/mail-servers`)

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| POST | `` | admin | Register server (+ optional immediate connect); seeds default settings; logs result |
| GET | `` | analyst+ | Server-management list (status, last connected, last error, has_credentials) |
| GET | `/{id}` | analyst+ | One server |
| POST | `/{id}/connect` | admin | Connect with stored credentials or rotate inline; failure → status `error` + error log |
| POST | `/{id}/disconnect` | admin | **Graceful** teardown: CYBERGUARD stops reading; the mail server keeps running; credentials retained |
| DELETE | `/{id}` | admin | Remove row (credentials + logs cascade); mail server unaffected |
| POST | `/{id}/fetch` | analyst+ | Pull recent messages (normalized shape, provider-tagged) + scan log entry |
| POST | `/{id}/quarantine` | analyst+ | Move one message to quarantine + quarantine log entry |
| GET | `/{id}/logs` | analyst+ | This server's own stream; filters `log_type`, `from_date`, `to_date`; paginated |
| GET | `/{id}/settings` | analyst+ (viewer 403) | Per-server settings |
| PUT | `/{id}/settings` | admin | Update settings (unknown key → 400); writes a connection log entry |

## RLS (migration 0010)

All predicates resolve membership through `cyberguard.org_member_role()`;
settings/logs reach the org through the parent `org_mail_servers` row:

- `org_mail_servers`: SELECT for members (API narrows listing to analyst+);
  writes admin.
- `org_mail_server_settings`: SELECT admin/analyst (**viewer blocked** at
  both RLS and API); writes admin.
- `org_mail_server_logs`: SELECT members; writes admin.

Suite 19 asserts raw-RLS cross-org isolation (0 rows for an outsider under
the app role) and the RBAC matrix.

## Frontend

- `/org/:orgId/mail-servers` — server-management table: Name, Provider,
  Status badge (green connected / grey disconnected / red error with
  last_error), Last Connected, encrypted-credentials indicator, and per-row
  Connect / Disconnect / Logs / Settings / Delete. "Add Mail Server" modal
  with provider-conditional credential fields (service-account JSON +
  delegated user; client id/secret/tenant; host/port/username/password).
- `/org/:orgId/mail-servers/:serverId/logs` — this server's stream with
  type filter and expandable metadata; empty state "No logs yet for this
  mail server".
- `/org/:orgId/mail-servers/:serverId/settings` — scan interval, quarantine
  toggle, auto-block toggle, quarantine expiry; Save → PUT.

Also linked from the Organization Dashboard module grid.
