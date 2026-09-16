# Gmail Pub/Sub Push Webhook (RT-3)

This document describes the configuration, operational guarantees, and validation flow for the real-time Gmail push notification webhook.

---

## 1. Google Cloud Pub/Sub Architecture

CYBERGUARD uses Google Cloud Pub/Sub push subscriptions to receive real-time mailbox change notifications from Gmail's `users.watch` API.

```
+---------------+      watch()      +-----------------------+
|  Gmail Mailbox| ----------------> | Google Cloud Pub/Sub  |
|  (New Email)  |                   | Topic:                |
+---------------+                   | cyberguard-gmail      |
                                    +-----------+-----------+
                                                | Push
                                                v HTTP POST
                                    +-----------------------+
                                    | CYBERGUARD Webhook    |
                                    | /api/v1/webhooks/gmail|
                                    +-----------+-----------+
                                                | Enqueue (<50ms)
                                                v
                                    +-----------------------+
                                    | Redis / Arq Queue     |
                                    | + PostgreSQL job_queue|
                                    +-----------------------+
```

### Setup Instructions
1. **Create Pub/Sub Topic**:
   ```bash
   gcloud pubsub topics create cyberguard-gmail
   ```
2. **Grant Gmail Publish Permissions**:
   Gmail's push service account (`gmail-api-push@system.gserviceaccount.com`) must have the `roles/pubsub.publisher` role on your topic:
   ```bash
   gcloud pubsub topics add-iam-policy-binding cyberguard-gmail \
       --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
       --role="roles/pubsub.publisher"
   ```
3. **Create Push Subscription**:
   Configure a push subscription targeting CYBERGUARD's webhook endpoint:
   ```bash
   gcloud pubsub subscriptions create cyberguard-gmail-push \
       --topic=cyberguard-gmail \
       --push-endpoint="https://api.yourdomain.com/api/v1/webhooks/gmail"
   ```

---

## 2. Authentication & Verification Tokens

To ensure only authentic Google Pub/Sub push messages are accepted:

- Set `GOOGLE_PUBSUB_VERIFICATION_TOKEN` in your environment (`.env`):
  ```env
  GOOGLE_PUBSUB_VERIFICATION_TOKEN=your-random-secret-verification-token
  ```
- Configure your Pub/Sub push subscription with either:
  1. A query parameter token:
     `https://api.yourdomain.com/api/v1/webhooks/gmail?token=your-random-secret-verification-token`
  2. A Bearer token header in the push subscription configuration.
- Optional JWT OIDC verification:
  Configure `GMAIL_PUBSUB_AUDIENCE` to validate the `aud` claim in Google-signed OIDC push tokens.
- When `GOOGLE_PUBSUB_VERIFICATION_TOKEN` is unset or empty, the webhook operates in development mode (verification skipped).

---

## 3. Example Request & Response

### Request Format
Google Pub/Sub sends an HTTP POST request with a JSON payload where `message.data` is base64-encoded:

```bash
# Example payload: {"emailAddress": "alice@example.com", "historyId": "123456"}
# Base64 data: eyJlbWFpbEFkZHJlc3MiOiAiYWxpY2VAZXhhbXBsZS5jb20iLCAiaGlzdG9yeUlkIjogIjEyMzQ1NiJ9

curl -X POST "http://localhost:8000/api/v1/webhooks/gmail?token=your-random-secret-verification-token" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "data": "eyJlbWFpbEFkZHJlc3MiOiAiYWxpY2VAZXhhbXBsZS5jb20iLCAiaGlzdG9yeUlkIjogIjEyMzQ1NiJ9",
      "messageId": "pubsub-msg-987654"
    },
    "subscription": "projects/my-project/subscriptions/cyberguard-gmail-push"
  }'
```

### Response Format
- **Success (Accepted)**:
  ```json
  {
    "status": "accepted",
    "job_id": "gmail_sync:usr_abc123:123456"
  }
  ```
- **Duplicate (Idempotent Acknowledgment)**:
  ```json
  {
    "status": "accepted",
    "job_id": "gmail_sync:usr_abc123:123456",
    "duplicate": true
  }
  ```
- **Ignored (Unknown / Paused Account)**:
  ```json
  {
    "status": "ignored",
    "reason": "unknown_email"
  }
  ```
- **Malformed / Unauthorized**:
  HTTP 400 `{"detail": "Invalid Pub/Sub message"}`

---

## 4. Thin Webhook Guarantee (<50ms Response)

The webhook endpoint is strictly asynchronous and non-blocking:
1. **Zero Gmail API Calls**: The webhook **never** calls Google APIs (no message fetching, no profile calls).
2. **Zero ML Inference**: The webhook **never** runs ML models, heuristic blending, or threat evaluation.
3. **Minimal Database Writes**: The webhook only queries `gmail_accounts` by email and idempotently inserts one row into `job_queue`. It **never** writes to `processed_emails` or scan tables.
4. **Sub-50ms Response Time**: Ingestion consists exclusively of token verification, base64 payload decoding, and queue dispatch.

---

## 5. Idempotency & Deduplication

Pub/Sub provides **at-least-once delivery**. A single mailbox change may trigger duplicate push events:
- **Deterministic Job ID**: `job_id = make_gmail_sync_job_id(owner_user_id, history_id)`.
- If a push notification with the same history ID arrives twice:
  1. The database checks `cyberguard.job_queue` for existing `job_id`.
  2. Redis/Arq deduplicates against in-flight jobs with the same `_job_id`.
  3. The endpoint returns 200 with `"duplicate": true` without creating redundant background work.

---

## 6. Rate Limiting (Gmail API Quota Protection)

Google Cloud enforces a user rate limit of 250 requests/second/user.
- An in-memory token bucket (`TokenBucketRateLimiter`) tracks requests per `(owner_user_id, "gmail_sync")`.
- When rapid bursts exhaust the token bucket, jobs are automatically enqueued with `defer_by=5s` in Arq.
- Rate-limit events are logged at WARNING level for observability.
