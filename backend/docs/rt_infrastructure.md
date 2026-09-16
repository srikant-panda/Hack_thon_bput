# Real-Time Pipeline Infrastructure (RT-1)

This document describes the real-time asynchronous background pipeline architecture for **CYBERGUARD**, powered by Redis and Arq.

---

## 1. Architecture Overview

```
+---------------------------------------------------------------------------------+
|                                FastAPI Web App                                  |
|            (Endpoints: /api/v1/..., /health, /ready, /metrics)                   |
+---------------------------------------+-----------------------------------------+
                                        |
                                        | Enqueue Jobs (Deterministic ID / UUID)
                                        v
+---------------------------------------------------------------------------------+
|                           Redis 7+ (In-Memory Broker)                           |
|                       Queue: "cyberguard_email" (Sorted Set)                    |
+-------------------+-----------------------------------------+-------------------+
                    |                                         |
                    | Poll / Pop                              | Poll / Pop
                    v                                         v
+-------------------------------------+   +---------------------------------------+
|            gmail-worker             |   |             email-worker              |
| (app.workers.gmail_worker)          |   | (app.workers.email_worker)            |
|                                     |   |                                       |
| - Gmail mailbox polling             |   | - Threat heuristic analysis           |
| - Push notification webhooks        |   | - XGBoost & ML model scoring          |
| - Message normalization             |   | - Autonomous SOAR enforcement         |
+------------------+------------------+   +-------------------+-------------------+
                   |                                          |
                   +--------------------+---------------------+
                                        |
                                        v
+---------------------------------------------------------------------------------+
|                           PostgreSQL & Storage Layer                            |
|             (SQLAlchemy 2.0 Async / RLS / Security History / Audit)             |
+---------------------------------------------------------------------------------+
```

---

## 2. Docker Compose Usage

CYBERGUARD provides a local development `docker-compose.yml` orchestrating Redis, Postgres, the FastAPI application, and dedicated Arq worker instances.

### Starting Local Services

```bash
cd backend
docker-compose -f docker-compose.yml up --build
```

### Services Breakdown

| Service | Image / Build | Port | Purpose |
|---|---|---|---|
| `redis` | `redis:7-alpine` | `6379` | In-memory queue broker and job store |
| `postgres` | `postgres:16-alpine` | `5432` | Local PostgreSQL database instance |
| `api` | `.` (uvicorn) | `8000` | FastAPI application server with hot-reload |
| `gmail-worker` | `.` (arq) | - | Dedicated worker for Gmail polling and sync |
| `email-worker` | `.` (arq) | - | Dedicated worker for threat analysis and SOAR |

> [!NOTE]
> In production environments, Redis is typically provided by a managed provider (e.g. AWS ElastiCache, Redis Cloud, or Upstash), and workers run as independent horizontally scalable container replicas.

---

## 3. Worker Entry Points

Each worker class inherits from `app.workers.base.WorkerSettings` and is executed via the `arq` CLI:

### Gmail Worker
```bash
uv run arq app.workers.gmail_worker.WorkerSettings
```
* **Queue**: `cyberguard_email`
* **Concurrency**: Configured via `ARQ_MAX_JOBS` (default: `10`)
* **Purpose**: Ingests Gmail message streams, handles webhook syncs, and avoids blocking API latency.

### Email Worker
```bash
uv run arq app.workers.email_worker.WorkerSettings
```
* **Queue**: `cyberguard_email`
* **Concurrency**: Configured via `ARQ_MAX_JOBS` (default: `10`)
* **Purpose**: Runs CPU/ML-heavy inspection pipelines (heuristics, XGBoost models, quarantine playbooks).

---

## 4. Health & Observability Endpoints

All probes are registered at both root (`/`) and the API prefix (`/api/v1/`):

### 1. `GET /health` (Liveness Probe)
Fast in-memory process health check returning immediate status:
```json
{
  "status": "ok",
  "timestamp": "2026-09-16T12:00:00.000000+00:00"
}
```

### 2. `GET /ready` (Readiness Probe)
Performs real connectivity verification against downstream dependencies:
* **PostgreSQL**: Runs `SELECT 1` on active database session.
* **Redis**: Issues `PING` command against configured `REDIS_URL`.

**Success (HTTP 200)**:
```json
{
  "status": "ok",
  "ready": true,
  "timestamp": "2026-09-16T12:00:00.000000+00:00",
  "details": {
    "postgres": "ok",
    "redis": "ok"
  }
}
```

**Degraded (HTTP 503 Service Unavailable)**:
```json
{
  "status": "unavailable",
  "ready": false,
  "timestamp": "2026-09-16T12:00:00.000000+00:00",
  "details": {
    "postgres": "ok",
    "redis": "error: Connection refused"
  }
}
```

### 3. `GET /metrics` (Prometheus Metrics)
Exposes Prometheus exposition text format for scraping orchestrator metrics:
```text
# HELP cyberguard_up CyberGuard service availability (1 = up)
# TYPE cyberguard_up gauge
cyberguard_up 1
# HELP cyberguard_build_info Build and version info
# TYPE cyberguard_build_info gauge
cyberguard_build_info{version="0.2.0"} 1
# HELP cyberguard_pipeline_events_total Total real-time events processed
# TYPE cyberguard_pipeline_events_total counter
cyberguard_pipeline_events_total 0
```

---

## 5. Graceful Shutdown Behavior

Arq provides native asynchronous signal handling for `SIGINT` and `SIGTERM`:
1. When `SIGTERM` or `SIGINT` is received, the worker immediately ceases pulling new jobs from Redis.
2. Active jobs continue execution up to `job_timeout` (default: 300 seconds).
3. Lifecycle shutdown hook (`on_shutdown`) runs to flush audit trails and close open sessions cleanly.
4. If jobs do not conclude within `job_completion_wait`, the worker terminates remaining tasks safely.

---

## 6. Job ID Conventions & Idempotency

To prevent duplicate job execution when webhooks or sync triggers retry:
* **Gmail Sync**: `f"gmail_sync:{user_id}:{history_id}"`
* **Email Scan**: `f"email_scan:{user_id}:{message_id}"`
* **Generic / One-off Tasks**: standard UUID4 string (`str(uuid.uuid4())`).

When an enqueued job ID already exists in Redis, `QueueClient.enqueue_job()` detects the existing job key and returns the existing `Job` instance rather than creating duplicates.

---

## 7. Configuration Reference

All settings can be specified via environment variables or `.env`:

| Setting | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379` | Redis DSN for queue broker connection |
| `ARQ_QUEUE_NAME` | `cyberguard_email` | Default queue name in Redis |
| `ARQ_MAX_JOBS` | `10` | Maximum concurrent jobs processed per worker process |
| `ARQ_JOB_TIMEOUT` | `300` | Job execution timeout in seconds before abort |
| `WORKER_CONCURRENCY` | `4` | Concurrency multiplier for worker thread/process scaling |
| `GOOGLE_PUBSUB_VERIFICATION_TOKEN` | `""` | Verification token validating incoming Pub/Sub push messages |
| `GMAIL_PUBSUB_TOPIC` | `projects/<project>/topics/cyberguard-gmail` | Google Cloud Pub/Sub topic for Gmail watch push notifications |
| `GMAIL_PUBSUB_AUDIENCE` | `None` | Optional expected JWT audience for Google-signed push tokens |

---

## 8. Real-Time Webhook Ingestion (RT-3)

CYBERGUARD provides a dedicated thin webhook endpoint (`POST /api/v1/webhooks/gmail`) for receiving Google Cloud Pub/Sub push notifications.

- **Non-Blocking Ingestion**: The webhook validates the push message, decodes the history ID, applies user rate limiting, inserts an idempotent job record into `cyberguard.job_queue`, and enqueues to Redis in `<50ms`.
- **Zero API or ML Overhead**: The webhook never calls Google APIs or runs ML models during request handling.
- **Deduplication**: Push retries with identical history IDs are matched against deterministic job IDs (`gmail_sync:{user_id}:{history_id}`) and acknowledged without re-executing.
- See [`gmail_webhook.md`](./gmail_webhook.md) for complete setup instructions, curl examples, and verification configuration.

