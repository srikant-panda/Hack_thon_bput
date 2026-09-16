# RT-5 — Email Fetch Worker Architecture & Design

## Overview
The Email Fetch Worker (`app.workers.email_worker.email_fetch_job`) executes asynchronous email retrieval, MIME parsing, content normalization, defensive sanitization, and downstream analysis job dispatching for the CyberGuard real-time email ingestion pipeline.

```
[ Gmail Sync Worker ] 
         │ (enqueues email_fetch:user_id:msg_id)
         ▼
[ Email Fetch Worker ]
         │ 1. Check idempotency (ProcessedEmail state)
         │ 2. Transition ProcessedEmail -> fetching
         │ 3. Fetch full message payload via GmailClient
         │ 4. Enforce Limits (10MB size cap, MIME parts cap)
         │ 5. Parse MIME via reused NormalizedMessage parser
         │ 6. Truncate body & sanitize HTML -> text (strip script/style)
         │ 7. Extract URLs & capture SPF/DKIM/DMARC auth headers
         │ 8. Store payload & transition ProcessedEmail -> fetched
         │ 9. Enqueue email_analysis:user_id:msg_id
         ▼
[ Email Analysis Worker ]
```

---

## Defensive Limits

All fetch operations enforce hard guardrails defined in `app/core/limits.py`:

| Constant | Limit | Behavior on Breach |
| :--- | :--- | :--- |
| `MAX_EMAIL_BYTES` | 10,000,000 bytes (10 MB) | Raises `NonRetryableError("size_exceeded")` -> routes directly to `dead_letter` on `job_queue` and sets `processed_emails.processing_status = 'failed'` with `failure_reason = 'size_exceeded'`. |
| `MAX_BODY_CHARS` | 200,000 chars | Body text and HTML strings are truncated to 200,000 characters to prevent excessive memory allocation. |
| `MAX_URLS` | 100 URLs | URLs extracted from body and links are capped at 100 deduplicated items; `truncated_urls: true` flag set in signals. |
| `MAX_MIME_PARTS` | 100 parts | MIME parts in complex payloads are truncated at 100 items; `truncated_parts: true` flag set in signals. |
| `FETCH_TIMEOUT_S` | 30 seconds | Client-side timeout for Google Gmail API `users.messages.get` HTTP requests. |
| `MAX_ATTACHMENT_META` | 20 items | Attachment metadata array stored in signals is capped at 20 attachments. |

---

## Poison Pill Isolation Policy

Malicious, malformed, or oversized payloads must not cause pipeline degradation or starvation for healthy accounts and messages:
1. **Oversized Payloads (`> 10 MB`)**:
   - `sizeEstimate` or payload byte count is evaluated before deep normalization.
   - Raises `NonRetryableError` with reason `size_exceeded`.
   - `email_fetch_job` intercepts `NonRetryableError` and immediately routes the job to `dead_letter` status with `retry_count = max_retries` and `next_retry_at = None`.
   - The associated `processed_emails` record is marked as `processing_status = 'failed'` with `failure_reason = 'size_exceeded'`.
   - Redis queue removes the job without retry backoff delays.

2. **Corrupted Payloads**:
   - Corrupted payloads trigger transient retries up to `max_retries` (default: 3) before transitioning into `dead_letter`.
   - Workers continue processing parallel healthy jobs without blocking or worker pool starvation.

---

## Security Invariants

1. **Zero Attachment Downloads**:
   - The worker only extracts attachment metadata: `filename`, `mime_type`, `size`, and `attachment_id`.
   - Zero bytes of attachment content are downloaded from the Gmail API (`users.messages.attachments.get` is never called).
2. **No HTML Rendering or Script Execution**:
   - HTML bodies are sanitized using text conversion (`sanitize_html_to_text`), stripping all `<script>`, `<style>`, and HTML markup tags.
   - No JavaScript runtime (V8, NodeJS) or browser automation tools (Playwright/Puppeteer) are invoked.

---

## Email Authentication Header Extraction

Authentication headers are parsed from `headers` and preserved in `signals`:
- `spf`: Extracted from `Received-SPF` (result like `pass`, `fail`, `neutral`, etc.).
- `dkim`: Extracted from `DKIM-Signature` (signature presence and selector).
- `dmarc`: Extracted from `Authentication-Results` (e.g. `dmarc=pass (p=reject)`).
- `return_path`: Extracted from `Return-Path` header for envelope-from verification.
