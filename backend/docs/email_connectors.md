# Email Connectors — Gmail (Phase 1-2)

Phase 1-2 adds the first real email connector: **Gmail**, using CYBERGUARD's
own Google Cloud OAuth client and encrypted backend token storage.
**Outlook, Yahoo, and iCloud are declared coming-soon/unsupported — they are
never faked.**

## Phase boundary

- **Phase 1-2 (this phase):** connect Gmail, validate mailbox access
  (`test_connection`), encrypted token vault, operation log.
- **Phase 3:** scan mailbox messages.
- **Phase 4:** quarantine / block senders.
- **Event email notifications: Phase 7 — not implemented yet.**

## Security model

1. **Supabase login tokens are not Gmail tokens.** Supabase Google sign-in is
   identity-only. Gmail access uses a separate Google Cloud OAuth client owned
   by CYBERGUARD (`GOOGLE_GMAIL_CLIENT_ID` / `GOOGLE_GMAIL_CLIENT_SECRET`).
2. **Gmail tokens are server-side only.** The frontend sees connector
   metadata (provider, provider email, status, scopes, capabilities, last
   test/sync, last error) — never access or refresh tokens.
3. **Tokens encrypted at rest** with `CONNECTOR_TOKEN_KEY`
   (Fernet; `app/core/crypto.py`). Plaintext exists only in runtime variables
   while a provider call executes and is never logged.
4. **RLS isolation.** `email_connector_accounts`, `connector_oauth_states`,
   and `connector_operation_logs` live in the `cyberguard` schema with owner
   policies keyed on `app.user_id`; the app connects as `cyberguard_api`
   (`NOBYPASSRLS`), so cross-user reads are denied in the database itself.
5. **OAuth state** rows are high-entropy, single-use, and expire after
   `CONNECTOR_OAUTH_STATE_TTL_SECONDS` (default 600 s). The callback carries
   no bearer token, so it consumes state via the service-role helper
   (`app/db/admin.py`) — owner identity comes from the state row, never from
   the browser. No tokens appear in redirect URLs.
6. **Honest failures.** Google errors map to safe classes:
   `reauth_required` (401/invalid_grant), `insufficient_scope` (403),
   `rate_limited` (429), `failed` (other). `GET /connectors/capabilities`
   reports the provider registry truthfully; unsupported providers declare
   `unsupported_reason`.

## Google Cloud setup

1. Create a Google Cloud project.
2. Enable the **Gmail API** (APIs & Services → Library).
3. Configure the **OAuth consent screen** in **Test** mode.
4. Add your account(s) as **test users**.
5. Create an **OAuth Web Client** (APIs & Services → Credentials).
6. Add the authorized redirect URI:
   ```text
   http://localhost:8000/api/v1/connectors/gmail/callback
   ```
7. Set the backend env:
   ```env
   GOOGLE_GMAIL_CLIENT_ID=<client id>
   GOOGLE_GMAIL_CLIENT_SECRET=<client secret>
   GOOGLE_GMAIL_REDIRECT_URI=http://localhost:8000/api/v1/connectors/gmail/callback
   FRONTEND_CONNECTORS_URL=http://localhost:5173/email-connectors
   CONNECTOR_TOKEN_KEY=<fernet key>
   GMAIL_CONNECTOR_ENABLED=true
   ```
   Generate the encryption key with:
   ```bash
   uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

Scopes requested: `https://www.googleapis.com/auth/gmail.modify` with
`access_type=offline` + `prompt=consent` (refresh token required; the callback
rejects a connection without one and asks the user to reconnect).

## API surface

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/v1/connectors/capabilities` | no | Provider registry with honest statuses |
| `GET /api/v1/connectors` | user | List caller's connectors (metadata only) |
| `POST /api/v1/connectors/gmail/authorize` | user | Create state; returns Google consent URL |
| `GET /api/v1/connectors/gmail/callback` | state | OAuth callback; redirects to `FRONTEND_CONNECTORS_URL` with `?connected=gmail&status=success\|error&reason=<safe>` |
| `POST /api/v1/connectors/{id}/test` | user | Live connection test via token manager |
| `DELETE /api/v1/connectors/{id}` | user | Disconnect: revoke (best-effort), clear tokens, keep row (`status=revoked`) |
| `GET /api/v1/connectors/operations` | user | Connector operation log |

## Modules

- `app/services/email_providers/` — provider contract (`base.py`), honest
  registry (`registry.py`), Gmail implementation (`gmail.py`).
- `app/services/connectors/oauth_service.py` — authorization URL + callback
  (state validation, code exchange, refresh-token requirement, upsert).
- `app/services/connectors/token_manager.py` — transparent access-token
  refresh (60 s expiry margin); `invalid_grant` marks `reauth_required`.
- `app/services/connectors/connector_service.py` — list/test/disconnect/
  serialize + operation logging.

## Manual setup status

- OAuth client configured: **no** (awaiting Google Cloud project setup)
- Gmail API enabled: **no**
- Test user added: **no**
- Callback URL verified live: **no** (flow verified with mocked Google
  responses in `scripts/test_email_connectors.py`, Suite 11)
