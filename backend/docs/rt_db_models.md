# Real-Time Pipeline Database Models (RT-2)

This document describes the schema architecture, entity relationships, state machines, idempotency controls, and cryptographic safeguards introduced in RT-2 for the real-time mailbox monitoring and threat processing pipeline.

---

## 1. Entity-Relationship Diagram (ASCII)

```
                       +-------------------------+
                       |      cyberguard.users   |
                       +-------------------------+
                       | id VARCHAR(64) [PK]     |
                       +------------+------------+
                                    | 1
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
          | *                       | *                       | *
+---------v---------------+ +-------v-----------------+ +-----v-------------------+
| cyberguard.             | | cyberguard.            | | cyberguard.             |
| gmail_accounts          | | job_queue              | | scan_results            |
+-------------------------+ +------------------------+ +-------------------------+
| id [PK]                 | | id [PK]                | | id [PK]                 |
| owner_user_id [FK] (RLS)| | owner_user_id [FK](RLS)| | owner_user_id [FK] (RLS)|
| email                   | | job_type               | | provider_message_id     |
| access_token_encrypted  | | job_id [UNIQUE]        | | verdict                 |
| refresh_token_encrypted | | status                 | | risk_score              |
| last_history_id         | | retry_count            | | scan_details JSONB      |
| watch_expiration        | | max_retries            | | created_at              |
| sync_status             | | payload JSONB          | +-----------+-------------+
| last_sync_at            | | result JSONB           |             | 0..1
| last_error              | | error                  |             |
| created_at, updated_at  | | next_retry_at          |             |
| UQ(owner_user_id, email)| | started_at             |             |
+------------+------------+ | completed_at           |             |
             | 1            | created_at, updated_at |             |
             |              +------------------------+             |
             | *                                                   |
+------------v-----------------------------------------------------+-------------+
| cyberguard.processed_emails                                                    |
+--------------------------------------------------------------------------------+
| id VARCHAR(36) [PK]                                                            |
| owner_user_id VARCHAR(64) [FK -> users.id] (RLS Key)                           |
| gmail_account_id VARCHAR(36) [FK -> gmail_accounts.id]                         |
| gmail_message_id VARCHAR(128)                                                  |
| subject TEXT, sender VARCHAR(255)                                              |
| received_at TIMESTAMPTZ                                                        |
| processing_status VARCHAR(32) [received|fetching|fetched|analyzing|analyzed|...] |
| risk_score FLOAT, classification VARCHAR(32)                                   |
| signals JSONB                                                                  |
| scan_result_id VARCHAR(36) [FK -> scan_results.id, NULLABLE]                    |
| created_at, updated_at TIMESTAMPTZ                                             |
| UNIQUE (owner_user_id, gmail_message_id)  <-- IDEMPOTENCY CONSTRAINT           |
+--------------------------------------------------------------------------------+
```

---

## 2. State Machine Transitions

### A. Job Queue (`JobQueue.status`)
The background job queue tracks the lifecycle of all distributed Arq worker tasks:
- `queued`: Task submitted to Redis/Arq queue, waiting for an available worker.
- `running`: Worker has dequeued the task (`started_at` populated).
- `completed`: Task finished successfully (`completed_at` populated, `result` stored).
- `failed`: Task failed with transient error; `retry_count` incremented, `next_retry_at` computed via exponential backoff schedule.
- `dead_letter`: Task reached `max_retries` (default 5); unrecoverable or permanently failing.

```
       +------------+
       |   queued   |<-----------------------+
       +-----+------+                        |
             | (worker picks up)             |
             v                               |
       +------------+                        |
       |  running   |                        | (failed -> queued,
       +-----+------+                        |  retry_count < max_retries)
             |                               |
     +-------+-------+                       |
     | (success)     | (transient error)     |
     v               v                       |
+----+--------+ +----+-------+---------------+
|  completed  | |   failed   |
+-------------+ +----+-------+
                     | (permanent error / retry_count >= max_retries)
                     v
                +----+--------+
                | dead_letter |
                +-------------+
```

**Backoff Schedule**:
Failures schedule retries with exponential backoff:
`5s` -> `30s` -> `2min (120s)` -> `10min (600s)` -> `30min (1800s)`.

### B. Email Processing (`ProcessedEmail.processing_status`)
Real-time email processing follows a unidirectional pipeline:
```
[received] -> [fetching] -> [fetched] -> [analyzing] -> [analyzed] -> [completed]
    |             |            |             |              |
    +-------------+------------+-------------+--------------+---> [failed]
```
- Any in-progress stage transitioning into unrecoverable failure terminates at `failed`.
- Reprocessing can reset `failed` to `received` or `fetching`.

### C. Gmail Account Sync Status (`GmailAccount.sync_status`)
- `active` -> `paused`, `error`
- `paused` -> `active`, `error`
- `error` -> `active` (upon token re-authentication or webhook refresh)

---

## 3. Idempotency Guarantees

Real-time webhook and push architectures are inherently at-least-once delivery systems. Duplicate Pub/Sub messages or network retries must not result in duplicate threat scans, double alerts, or repeated enforcement actions.

1. **Email Idempotency (`ProcessedEmail`)**:
   - Enforced by database constraint: `UNIQUE (owner_user_id, gmail_message_id)`.
   - Ingestion service calls `ensure_processed_email()`. On duplicate key violation (`IntegrityError`), the transaction rolls back safely to savepoint and fetches the existing row.
   - If `existing.processing_status == 'completed'`, the pipeline halts processing immediately.

2. **Job Idempotency (`JobQueue`)**:
   - Enforced by database constraint: `UNIQUE (job_id)` with deterministic job ID derivation (`job_gmail_sync_<acc_id>_<history_id>` or `job_email_scan_<msg_id>`).
   - Ingestion service calls `ensure_job()`. If the job exists and its status is `running` or `completed`, redundant queuing is skipped.

3. **History Checkpoint Serialization (`GmailAccount`)**:
   - Updates to `last_history_id` lock the account row with `SELECT ... FOR UPDATE` via `update_history_id()`.
   - Concurrent worker tasks processing history batches are strictly serialized at the row level, preventing race conditions or out-of-order checkpoint regression.

---

## 4. Row-Level Security (RLS) Policies

All tables reside in the dedicated `cyberguard` schema and are protected by PostgreSQL RLS with `cyberguard_api` (NOBYPASSRLS):

- `cyberguard.gmail_accounts`
- `cyberguard.job_queue`
- `cyberguard.processed_emails`
- `cyberguard.scan_results`

Each table implements owner-scoped policies:
```sql
ALTER TABLE cyberguard.<table_name> ENABLE ROW LEVEL SECURITY;

CREATE POLICY <table_name>_select ON cyberguard.<table_name>
    FOR SELECT TO cyberguard_api
    USING (owner_user_id = current_setting('app.user_id', true)::text);

CREATE POLICY <table_name>_insert ON cyberguard.<table_name>
    FOR INSERT TO cyberguard_api
    WITH CHECK (owner_user_id = current_setting('app.user_id', true)::text);

CREATE POLICY <table_name>_update ON cyberguard.<table_name>
    FOR UPDATE TO cyberguard_api
    USING (owner_user_id = current_setting('app.user_id', true)::text)
    WITH CHECK (owner_user_id = current_setting('app.user_id', true)::text);

CREATE POLICY <table_name>_delete ON cyberguard.<table_name>
    FOR DELETE TO cyberguard_api
    USING (owner_user_id = current_setting('app.user_id', true)::text);
```

- **Cross-User Isolation**: An authenticated session under User A sees zero rows belonging to User B.
- **Admin/Service Role**: Service-level workflows (dashboards, system maintenance) connect using superuser/service-role sessions which bypass RLS when cross-tenant visibility is required.

---

## 5. Token Encryption Approach

- Google OAuth tokens (`access_token` and `refresh_token`) are encrypted at rest using AES-128 in CBC mode with PKCS7 padding and HMAC-SHA256 authentication (Fernet).
- Encryption/decryption keys are derived from the server environment variable `CONNECTOR_TOKEN_KEY`.
- Models provide safe accessors (`set_access_token`, `get_access_token`, `set_refresh_token`, `get_refresh_token`). Plaintext tokens are never written to database columns, query logs, or serialization payloads.
