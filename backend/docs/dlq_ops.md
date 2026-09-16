# Dead Letter Queue (DLQ) Operations & Retry Policy Architecture

This document details the architecture, retry policies, manual recovery workflows, auditability guarantees, and operator dashboard interfaces for CYBERGUARD's Dead Letter Queue (DLQ) subsystem.

---

## 1. DLQ Subsystem Architecture

The real-time ingestion and threat detection pipeline processes asynchronous jobs across decoupled worker processes (`gmail-worker`, `email-worker`, and `scheduler-worker`) orchestrated via Redis/Arq and tracked in PostgreSQL (`job_queue` table).

### State Machine Lifecycle

```
                  ┌──────────────┐
                  │    QUEUED    │◄────────────────┐
                  └──────┬───────┘                 │
                         │                         │
                         ▼                         │
                  ┌──────────────┐                 │
                  │   RUNNING    │                 │
                  └──┬────────┬──┘                 │
                     │        │                    │
          Success    │        │  Failure           │  Admin Manual Retry
                     ▼        ▼                    │  (POST /dlq/jobs/:id/retry)
             ┌───────────┐ ┌──────────┐            │
             │ COMPLETED │ │  FAILED  ├────────────┤
             └───────────┘ └──┬───────┘ (transient │
                              │          retries)  │
           Fatal / Exhausted  │                    │
                              ▼                    │
                      ┌─────────────┐              │
                      │ DEAD_LETTER ├──────────────┘
                      └──────┬──────┘
                             │  Admin Soft-Delete
                             ▼  (DELETE /dlq/jobs/:id)
                      ┌─────────────┐
                      │   DELETED   │
                      └─────────────┘
```

- **Queued**: Awaiting worker pickup from Redis stream/list.
- **Running**: Worker assigned, executing processing steps with correlation ID bound in `contextvars`.
- **Completed**: Execution succeeded, result payload persisted.
- **Failed**: Transient error encountered; scheduled for retry using category-specific exponential backoff curve.
- **Dead Letter**: Unrecoverable poison message, authentication revocation, or exhausted retries. Removed from active queues to prevent pool starvation.
- **Deleted**: Soft-deleted by administrator to clear operational view while retaining full forensic audit trail.

---

## 2. Retry Policy & Backoff Tuning Matrix

Errors are intercepted in `job_state_service` and classified using `app/core/retry_policy.py`:

| Error Classification | Underlying Exceptions / Signals | Max Retries | Retry Schedule / Backoff Delays | Jitter Enabled | Next State on First Failure | Operational Rationale |
|---|---|---|---|---|---|---|
| **Authentication Error** | `GmailAuthError` (HTTP 401, token revoked, `invalid_grant`) | 0 (No retry) | Immediate Dead Letter | No | `dead_letter` | OAuth token is invalid or revoked. Retrying consumes API quota and worker threads fruitlessly. Requires user re-authentication. |
| **Poison Pill Payload** | `MIMECorruptionError`, `OversizedEmail` (>10MB, corrupted boundaries) | 0 (No retry) | Immediate Dead Letter | No | `dead_letter` | Payload structure violates RFC specifications or exceeds buffer safety limits. Retrying will always fail and risks crashing workers. |
| **Rate Limit / Quota** | `GmailRateLimitError` (HTTP 429, user rate limit exceeded) | 5 | 30s, 5m, 30m, 2h, 6h | Yes (±10%) | `failed` (re-enqueued) | Upstream provider quota exhausted. Extended multi-hour backoff curve allows token buckets to refill; random jitter prevents thundering herd. |
| **Server / Network Transient** | `GmailServerError` (5xx), `NetworkTimeout`, upstream TCP reset | 5 | 5s, 30s, 2m, 10m, 30m | No | `failed` (re-enqueued) | Transient infrastructure or network hiccups. Standard exponential backoff allows rapid recovery once upstream stabilizes. |

### Configuration Tuning (`config.py`)

- `RETRY_BASE_DELAY_S`: Base delay unit (default: `5` seconds).
- `RETRY_MAX_RETRIES`: Default maximum retry attempts for transient jobs (default: `5`).
- `RETRY_JITTER_ENABLED`: Randomizes delays by ±10% to prevent synchronized worker retry thundering herds (default: `True`).

---

## 3. DLQ API Routes (`/api/v1/dlq`)

All DLQ endpoints enforce role-based access control (RBAC). Analysts receive HTTP 403 Forbidden. Admins have cross-tenant inspection and management privileges.

| Method | Endpoint | Authorization | Description |
|---|---|---|---|
| `GET` | `/api/v1/dlq/stats` | Admin | Returns aggregate metrics: `{ total_dead_letter, by_job_type, oldest_age_hours }`. |
| `GET` | `/api/v1/dlq/jobs` | Admin | Paginated list of dead-letter jobs. Filters: `job_type`, `from_date`, `to_date`, `owner_user_id`. |
| `GET` | `/api/v1/dlq/jobs/{job_id}` | Admin | Detailed view including full input payload, error stack trace, and timeline of retry attempts. |
| `POST` | `/api/v1/dlq/jobs/{job_id}/retry` | Admin | Resets `retry_count=0`, status=`queued`, re-enqueues job to Redis, logs admin audit record. |
| `DELETE` | `/api/v1/dlq/jobs/{job_id}` | Admin | Soft-deletes job (sets status=`deleted`), excludes from DLQ dashboard, logs admin audit record. |

---

## 4. Manual Retry & Soft-Delete Workflow

### Manual Re-enqueue (Retry)

When an administrator corrects an external condition (e.g., user reconnects OAuth account, or upstream server outage resolves):
1. Admin triggers `POST /api/v1/dlq/jobs/{job_id}/retry`.
2. The transaction resets `job.status = 'queued'`, `job.retry_count = 0`, `job.error = None`.
3. An audit row is created in `audit_logs` (`actor_type='user'`, `action='manual_dlq_retry'`).
4. The job payload is dispatched into Redis queue with its original `job_id`.
5. Worker pool resumes execution with a clean retry budget.

### Soft-Deletion

1. Admin triggers `DELETE /api/v1/dlq/jobs/{job_id}`.
2. The job is transitioned to `status = 'deleted'`.
3. An audit row is recorded in `audit_logs` (`action='manual_dlq_delete'`).
4. The record is permanently hidden from dead-letter queries while remaining in PostgreSQL for legal and forensic compliance.

---

## 5. Frontend DLQ Dashboard Usage

The frontend console is accessible at `/dlq` (gated by `<RoleGuard minimumRole="admin">`):
- **Realtime Status Pill**: Displays `LIVE` when connected to Supabase Realtime websocket events on `job_queue`. Falls back cleanly to 20s polling with `POLLING` badge if websockets are unavailable or offline.
- **KPI Stats Cards**:
  - *Total Dead Letters*: Highlights volume with alert styling if > 0.
  - *Oldest Age*: Highlights oldest lingering dead-letter task in hours.
  - *Job Type Breakdown*: Filter pills showing distribution across `gmail_sync`, `email_fetch`, and `email_analysis`.
- **Operational Table**: Displays job ID, job type, tenant owner, failure cause snippet, retry attempt count, and relative age.
- **Detail Slide-Over Drawer**:
  - Full formatted JSON payload viewer with one-click copy.
  - Complete error stack trace.
  - Attempt-by-attempt retry history timeline.
  - Correlation ID with direct link into `/audit-logs`.
