# Security History & Audit (Phase 5)

Phase 5 adds a **permanent security history** for real security events and
real provider operations, an automated-vs-user audit distinction, and a
**review view** for flagged emails. Temporary AI chat history remains strictly
session-scoped and separate from this permanent record.

## What gets recorded

Every row in `cyberguard.security_events` reflects a **real** operation — the
`operation_status` / `operation_detail` always carry the actual provider
result (success, failed, insufficient_scope, reauth_required…), never a
default success.

| Event type | Emitted by | Actor |
|---|---|---|
| `scan_verdict` | scan route after each analyzed message | `system` |
| `quarantine` | action engine (auto) — also on failure with the real error class | `system` |
| `release` | manual release; scheduler auto-release on expiry | `user` / `scheduler` |
| `keep` | manual "keep quarantined" review outcome (no provider action) | `user` |
| `delete` | manual delete (trash or permanent per settings) | `user` |
| `sender_block` | action engine creating a Gmail filter | `system` |
| `sender_release` | manual unblock (filter id in detail) | `user` |
| `sender_expiry` | scheduler removing an expired filter (rule id in detail) | `scheduler` |
| `connector_connect` / `connector_disconnect` / `connector_test` | connector lifecycle | `user` |

Each flagged-email record carries: connector, provider, message id, sender,
subject, severity, score, verbose explanation, indicator list, action
requested, action performed, actor type, operation status/detail, timestamps,
and links to the related quarantined item / blocked sender.

Every event also writes a matching `audit_logs` row with the same
`actor_type`, so the audit trail distinguishes **user / system / scheduler**.

## Privacy boundaries

- Tokens and plaintext secrets never appear in history or audit rows.
- **AI chat content is never written to history or audit.** The assistant
  audit entry keeps the intent class only (`[OPS_STATS]` etc.); its details no
  longer contain user message text.
- Chat history lives **only** in `sessionStorage` under a per-tab key
  (`cyberguard_assistant_chat_<tab-uuid>`) and is destroyed when the tab
  closes (`pagehide`/`beforeunload`/unmount). The drawer states:
  "Session-only — history is discarded when this tab closes."

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/security-history` | Owner-scoped, filters: `event_type`, `actor_type`, `severity`, `sender_email` (ilike), `from`, `to`; `limit`/`offset`; newest first |
| `GET /api/v1/security-history/{id}` | Full event incl. indicators |
| `GET /api/v1/quarantine/{item_id}/review` | Review record: item + message metadata + stored ScanResult + **ordered event chain** for the message + `available_actions` computed from status, connector readiness, and the permanent-delete setting |
| `POST /api/v1/enforcement/quarantine/{id}/keep` | Manual review outcome "keep quarantined" (no provider action) |

`available_actions` logic: released/deleted items no longer offer release;
`permanent_delete_enabled=false` offers delete as `trash`-only; a disconnected
connector offers nothing (`connector_ready=false`).

## Backfill

`scripts/backfill_security_history.py` creates history rows from
pre-Phase-5 data (one-time, idempotent — a source row already referenced by a
`security_event` is skipped; run twice to verify no duplicates). Sources:
`quarantined_items` → `quarantine` events, `blocked_senders` →
`sender_block` events, terminal `connector_operation_logs` → connector
lifecycle events.

## Migration

`0006_security_history`: creates `cyberguard.security_events` (RLS owner
policy on `app.user_id`, composite index `(owner_user_id, created_at DESC)`)
and adds `audit_logs.actor_type` (backfilled to `'user'`). Downgrade reverses
both.
