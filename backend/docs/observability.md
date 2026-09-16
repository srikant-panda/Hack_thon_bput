# CyberGuard Real-Time Pipeline Observability Specification

This document details the observability architecture for CyberGuard's asynchronous email security and real-time ingestion pipelines. It covers structured JSON logging, distributed correlation ID propagation, Prometheus metrics instrumentation, sensitive credential redaction, log aggregation, and Grafana dashboarding.

---

## 1. Architecture Overview

CyberGuard's ingestion and threat evaluation workflow operates across decoupled microservices and asynchronous workers:

```
+---------------------+       +-----------------------+       +-----------------------+
| Google Cloud Pub/Sub| ----> | routes_gmail_webhook  | ----> | Redis / Arq Queue     |
+---------------------+       +-----------------------+       +-----------------------+
                                                                          |
                                                                          v
+---------------------+       +-----------------------+       +-----------------------+
| email-worker        | <---- | email-worker          | <---- | gmail-worker          |
| (email_analysis)    |       | (email_fetch)         |       | (gmail_sync)          |
+---------------------+       +-----------------------+       +-----------------------+
           |
           v
+---------------------+       +-----------------------+
| Supabase Realtime   |       | Prometheus Exporter   |
| (Quarantine UI)     |       | (/metrics)            |
+---------------------+       +-----------------------+
```

Every stage emits structured JSON logs bound to an immutable `correlation_id` and records low-overhead Prometheus metrics for real-time monitoring and alerting.

---

## 2. Structured JSON Log Format Specification

Every log entry emitted by the backend application or background workers is formatted as a single-line JSON object by `StructuredJsonFormatter` in `app/core/logging_config.py`.

### 2.1 JSON Schema

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | `string` | Human-readable ISO timestamp with millisecond precision (`YYYY-MM-DD HH:MM:SS,mmm`). |
| `level` | `string` | Log severity level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |
| `logger` | `string` | Logger namespace (e.g. `cyberguard.worker`, `cyberguard.gmail.sync`). |
| `message` | `string` | Sanitized human-readable log message. |
| `correlation_id` | `string \| null` | Unique trace ID traversing all downstream worker tasks for the event. |
| `job_id` | `string \| null` | Unique deterministic identifier of the current task queue job. |
| `job_type` | `string \| null` | Task category (`gmail_sync`, `email_fetch`, `email_analysis`, `watch_renewal`, `reconciliation`). |
| `user_id` | `string \| null` | Authenticated tenant or mailbox owner UUID. |
| `worker_name` | `string \| null` | Worker identity (`gmail-worker`, `email-worker`, `scheduler-worker`). |
| `exception` | `string` *(optional)* | Formatted stack trace when exception info is present. |

### 2.2 Structured Log Example

```json
{
  "timestamp": "2026-09-16 17:04:16,339",
  "level": "INFO",
  "logger": "cyberguard.worker",
  "message": "email_fetch end: correlation_id=email_fetch:user_789:msg_abc123",
  "correlation_id": "email_fetch:user_789:msg_abc123",
  "job_id": "email_fetch:user_789:msg_abc123",
  "job_type": "email_fetch",
  "user_id": "user_789",
  "worker_name": "email-worker"
}
```

### 2.3 Log Level Conventions

- **`INFO`**: High-level lifecycle transitions, job start/end notices, account discoveries, and threat verdicts.
- **`DEBUG`**: Internal parsing steps, header inspections, heuristic score details, and cache queries.
- **`WARNING`**: Transient API rate limits (429), exponential backoff retries, and recoverable synchronization delays.
- **`ERROR`**: Fatal errors, token revocation/auth errors (401), invalid schema payloads, and unrecoverable exceptions.

---

## 3. Sensitive Data Filter & Redaction

To maintain strict compliance (GDPR, SOC2, HIPAA), CyberGuard enforces a zero-credential-leak policy via `SensitiveDataFilter`. Before log serialization, log messages and extra arguments are evaluated against pre-compiled regex filters.

### 3.1 Redaction Rules

1. **OAuth Access Tokens**: `ya29.[a-zA-Z0-9_\-\.]+` -> `[REDACTED_TOKEN]`
2. **OAuth Refresh Tokens**: `1//[a-zA-Z0-9_\-\.]+` -> `[REDACTED_TOKEN]`
3. **Bearer Authorization Headers**: `Bearer [a-zA-Z0-9_\-\.]+` -> `Bearer [REDACTED_TOKEN]`
4. **Client Secrets & Passwords**: `password="..."` or `client_secret="..."` -> `[REDACTED_SECRET]`
5. **Raw Email Bodies**: `body="..."` or `body_text="..."` -> `[REDACTED_BODY]`
6. **Attachment Byte Payloads**: `attachment_data="..."` or `content_bytes="..."` -> `[REDACTED_ATTACHMENT_DATA]`

---

## 4. Correlation ID Flow & Context Propagation

Correlation IDs track a single email event across independent processes:

1. **Webhook Ingestion**: When Google Cloud Pub/Sub pushes a notification to `POST /webhooks/gmail`, a deterministic ID is resolved (`gmail_sync:{owner_user_id}:{history_id}`).
2. **Context Binding**: When a worker picks up the job (`gmail_sync_job`), `job_context()` sets `current_correlation_id` in `contextvars.ContextVar`.
3. **Downstream Enqueue**: When `sync_service` discovers messages, it generates deterministic child job IDs (`email_fetch:{owner_user_id}:{message_id}`) and enqueues them.
4. **Subsequent Worker Propagation**: The fetch worker uses `job_context()`, maintaining trace linkage through `email_analysis` and final `ScanResult` emission.
5. **Context Cleanup**: Upon task completion (whether successful or aborted via exception), `clear_log_context()` ensures zero leakage into subsequent jobs on the same worker thread.

---

## 5. Prometheus Metrics Catalog

All metrics are exposed at `GET /metrics` in standard Prometheus text exposition format (version 0.0.4).

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `gmail_events_received_total` | Counter | `owner_user_id` | Total Pub/Sub push notification events received by the webhook endpoint. |
| `gmail_sync_jobs_total` | Counter | `status` (`success`, `failed`) | Total Gmail mailbox history synchronization jobs executed. |
| `email_fetch_jobs_total` | Counter | `status`, `failure_reason` | Total raw message fetch and MIME normalization jobs executed. |
| `email_analysis_jobs_total` | Counter | `status`, `classification` | Total threat analysis jobs evaluated (`phishing`, `safe`, `suspicious`). |
| `job_processing_duration_seconds` | Histogram | `job_type` | Job execution duration distribution (buckets: `0.1`, `0.5`, `1.0`, `5.0`, `10.0`, `30.0`, `60.0`). |
| `queue_depth` | Gauge | `queue_name` | Current depth of pending jobs in Redis queue (`cyberguard:queue`). |
| `dead_letter_jobs_total` | Counter | `job_type` | Total unrecoverable poison pill jobs transitioned directly to `dead_letter`. |
| `gmail_api_errors_total` | Counter | `error_type` (`auth`, `rate_limit`, `server`) | Total Google API errors categorized by failure type. |
| `processed_emails_total` | Counter | `classification` (`safe`, `phishing`, `suspicious`) | Total processed emails classified by CyberGuard threat engines. |
| `worker_jobs_total` | Counter | `worker_name`, `job_type`, `status` | Total jobs executed by worker instance (`gmail-worker`, `email-worker`, `scheduler-worker`). |

---

## 6. Prometheus Scraping Configuration

Add the following scrape target to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "cyberguard-backend"
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: "/metrics"
    scheme: "http"
    static_configs:
      - targets: ["cyberguard-api:8000"]
        labels:
          environment: "production"
          service: "cyberguard"
```

---

## 7. Grafana Dashboard JSON

An excerpt of recommended Grafana dashboard panels for monitoring CyberGuard pipeline health:

```json
{
  "title": "CyberGuard Real-Time Ingestion & Threat Detection",
  "panels": [
    {
      "title": "Queue Depth (Redis)",
      "type": "gauge",
      "targets": [
        { "expr": "queue_depth{queue_name=\"cyberguard:queue\"}" }
      ]
    },
    {
      "title": "Pipeline Ingestion Rate (events/sec)",
      "type": "timeseries",
      "targets": [
        { "expr": "rate(gmail_events_received_total[1m])", "legendFormat": "Events ({{owner_user_id}})" },
        { "expr": "rate(email_analysis_jobs_total[1m])", "legendFormat": "Analyses ({{classification}})" }
      ]
    },
    {
      "title": "Job Duration (p95)",
      "type": "timeseries",
      "targets": [
        { "expr": "histogram_quantile(0.95, sum(rate(job_processing_duration_seconds_bucket[5m])) by (le, job_type))", "legendFormat": "{{job_type}} p95" }
      ]
    },
    {
      "title": "Gmail API Errors",
      "type": "timeseries",
      "targets": [
        { "expr": "increase(gmail_api_errors_total[5m])", "legendFormat": "{{error_type}}" }
      ]
    }
  ]
}
```

---

## 8. Centralized Log Aggregation Setup

### 8.1 Grafana Loki (via Promtail)

Configure Promtail to parse structured JSON logs and extract `correlation_id` and `worker_name` as indexed labels:

```yaml
scrape_configs:
  - job_name: "cyberguard-logs"
    static_configs:
      - targets: ["localhost"]
        labels:
          job: "cyberguard"
          __path__: "/var/log/cyberguard/*.log"
    pipeline_stages:
      - json:
          expressions:
            timestamp: timestamp
            level: level
            logger: logger
            correlation_id: correlation_id
            job_type: job_type
            worker_name: worker_name
      - labels:
          level:
          job_type:
          worker_name:
      - timestamp:
          source: timestamp
          format: "2006-01-02 15:04:05,000"
```

### 8.2 Elastic Stack (Logstash / Filebeat)

Filebeat configuration reading standard container stdout JSON:

```yaml
filebeat.inputs:
  - type: container
    paths:
      - /var/lib/docker/containers/*/*.log
    processors:
      - decode_json_fields:
          fields: ["message"]
          target: ""
          overwrite_keys: true
```
