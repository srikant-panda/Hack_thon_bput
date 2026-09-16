# Scheduled Workers & Pub/Sub Safety Nets (RT-8)

This document describes the automated scheduled cron workers that act as safety nets for the real-time Gmail push notification ingestion pipeline.

---

## 1. Overview & Architecture

While Google Cloud Pub/Sub provides near-real-time push delivery when incoming messages arrive at a Gmail mailbox, two critical operational risks exist:

1. **Watch Expiration**: Gmail `users.watch` subscriptions automatically expire after **7 days**. If a watch expires without renewal, Google stops dispatching Pub/Sub notifications entirely.
2. **Dropped / Missed Notifications**: If Redis, worker nodes, or network connectivity experience transient downtime or partition, Pub/Sub push messages may fail or expire from retry topics, leaving mailboxes silently desynchronized.

The `scheduler-worker` runs periodic background cron routines to mitigate both failure modes without requiring manual SOC analyst intervention.

```
+-----------------------------------------------------------------------------------------+
|                                  Scheduler Worker                                       |
|                                                                                         |
|  +---------------------------------------+     +-------------------------------------+  |
|  |             renew_watches             |     |      reconcile_stuck_accounts       |  |
|  |     (4x daily: 00:00, 06:00, 12:00,   |     |       (2x hourly: :15, :45)         |  |
|  |                 18:00)                |     +-------------------------------------+  |
|  +---------------------------------------+                        |                     |
|                      |                                            |                     |
|       Watch Expiring (<24h buffer)?               Inactivity (>2h) or Transient Error?  |
|                      |                                            |                     |
|                      v                                            v                     |
|          POST /users/me/watch                       Enqueue deterministic gmail_sync:   |
|         (INBOX, GMAIL_PUBSUB_TOPIC)            gmail_sync:{user_id}:reconciliation      |
|                      |                                            |                     |
|                      v                                            v                     |
|         Update watch_expiration                       Redis Arq Queue / Workers         |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Cron Schedule Specification

| Job Name | Schedule (Cron) | Frequency | Primary Function | Failure / Error Policy |
| :--- | :--- | :--- | :--- | :--- |
| `renew_watches` | `0 0,6,12,18 * * *` | 4x daily | Extends expiring Gmail `users.watch` subscriptions | Marks 401/403 as `reauth_required`; skips transient 429/5xx for next run |
| `reconcile_stuck_accounts` | `15,45 * * * *` | 2x hourly | Discovers missed messages for inactive accounts or transient errors | Skips fatal errors (`reauth_required`, `scope_error`); enqueues deterministic sync job |

---

## 3. Watch Renewal Service (`watch_service.py`)

### Eligibility Criteria
Queries accounts in `cyberguard.gmail_accounts` where:
- `watch_expiration < now() + 24 hours` OR `watch_expiration IS NULL`
- `sync_status != 'paused'`

### Workflow
1. Decrypts stored OAuth tokens via Fernet (`account.get_access_token()`, `account.get_refresh_token()`).
2. Invokes `GmailClient.watch(access_token, topic=GMAIL_PUBSUB_TOPIC, labels=['INBOX'])`.
3. Converts the returned epoch millisecond string or integer (`expiration`) to a timezone-aware UTC datetime.
4. On success:
   - Sets `watch_expiration = converted_datetime`
   - Sets `sync_status = 'active'`
   - Clears `last_error = None`
   - Updates `updated_at = now()`
5. On authentication failure (HTTP 401 Unauthorized / 403 Forbidden):
   - Sets `sync_status = 'error'`
   - Sets `last_error = 'reauth_required'`
6. On transient failures (HTTP 429 Too Many Requests / 5xx Server Error):
   - Emits structured warning log.
   - Skips account without updating status, allowing subsequent cron executions to retry.

---

## 4. Reconciliation Service (`reconciliation_service.py`)

### Eligibility Criteria
Queries accounts meeting either condition:
1. **Inactivity**: `sync_status == 'active'` AND (`last_sync_at < now() - 2 hours` OR `last_sync_at IS NULL`).
2. **Transient Error Recovery**: `sync_status == 'error'` AND `last_error NOT IN ('reauth_required', 'scope_error')` (e.g. temporary rate limits, network timeouts).

### Idempotent Enqueueing
- Generates a deterministic job ID: `gmail_sync:{owner_user_id}:reconciliation`.
- Calls `ensure_job` to register the job in `cyberguard.job_queue` under the account's `owner_user_id`. Unique constraints prevent duplicate rows from being inserted if reconciliation runs repeatedly.
- Calls `enqueue("gmail_sync", ...)` to dispatch the job to Redis. If already present in Redis, Arq reuses the existing job instance without spawning duplicate tasks.

---

## 5. Docker Compose Service Registration

The scheduler worker runs as an independent container service configured in `backend/docker-compose.yml`:

```yaml
  scheduler-worker:
    build: .
    command: uv run arq app.workers.scheduler_worker.WorkerSettings
    depends_on: [redis, postgres]
    environment: [REDIS_URL=redis://redis:6379]
    volumes: [".:/app"]
```
