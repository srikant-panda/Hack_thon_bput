# RT-6 — Email Analysis Worker Architecture & Design

## Overview
The Email Analysis Worker (`app.workers.email_worker.email_analysis_job`) runs threat detection heuristics, ML inference, monotonic score blending, result persistence, and real-time event broadcasting for the CyberGuard real-time ingestion pipeline.

```
[ Email Fetch Worker ]
         │ (enqueues email_analysis:owner_user_id:msg_id)
         ▼
[ Email Analysis Worker ]
         │ 1. Load ProcessedEmail (FOR UPDATE row lock)
         │ 2. Check Idempotency (skip if not 'fetched')
         │ 3. Transition ProcessedEmail -> 'analyzing'
         │ 4. Extract body, URLs, headers, and signals
         │ 5. Execute Reused Detection Engines:
         │    ├── Phishing Heuristics (analyze_email_heuristics)
         │    ├── URL Forensics (analyze_url_heuristics per URL)
         │    ├── Impersonation Heuristics (analyze_impersonation_heuristics)
         │    └── Auth Signal Verification (SPF / DKIM / DMARC)
         │ 6. Run Trained ML Models & Monotonic Blending:
         │    ├── Email Phishing XGBoost v2 (predict_email)
         │    ├── URL XGBoost v2 (predict_url)
         │    └── final_score = max(heuristic, 0.45*heuristic + 0.55*ml)
         │ 7. Aggregate Risk Score & Determine Classification:
         │    ├── >= 0.70 -> phishing
         │    ├── 0.35 - 0.69 -> suspicious
         │    └── < 0.35 -> safe
         │ 8. Update ProcessedEmail (status -> 'analyzed')
         │ 9. Persist ScanResult (scan_results table) with top indicators & explanation
         │ 10. Link ProcessedEmail.scan_result_id & transition status -> 'completed'
         │ 11. Trigger Realtime Notification Hook (notify_email_processed)
         ▼
[ Supabase Realtime / Security Events Stream ]
```

---

## Engine Reuse Architecture

To preserve single source of truth across manual and real-time pipelines, the worker strictly reuses the existing, production-proven detection engines:

| Engine | Module / Function | Inputs | Outputs |
| :--- | :--- | :--- | :--- |
| **Phishing** | `app.services.phishing_detector.analyze_email_heuristics` | `sender`, `subject`, `body_text` | Text indicators, lookalike domain, urgency, credential request patterns. |
| **URL Forensics** | `app.services.url_detector.analyze_url_heuristics` | `urls` (extracted in RT-5) | IP host, random paths, suspicious TLDs, top-1m reputation, brand in subdomain. |
| **Impersonation** | `app.services.impersonation_detector.analyze_impersonation_heuristics` | `f"{subject}\n{body_text}"`, `claimed_identity` | Authority claims (CEO/CFO/IT), pressure tactics, wire transfer / gift card fraud. |
| **Authentication** | Extracted from MIME headers in RT-5 | `spf`, `dkim`, `dmarc` | Auth failure indicators adjusting heuristic risk score. |

---

## Monotonic ML Blending Formula

The blending formula ensures that machine learning inference can elevate a heuristic threat assessment, but can never suppress or override concrete heuristic evidence:

$$\text{blended} = 0.45 \times \text{heuristic} + 0.55 \times \text{ml}$$
$$\text{final\_score} = \max(\text{heuristic}, \text{blended})$$

### Behavior Examples:
- **Heuristic = 0.60, ML = 0.90**:
  $$\text{blended} = 0.45(0.60) + 0.55(0.90) = 0.270 + 0.495 = 0.765 \implies \text{final} = \max(0.60, 0.765) = \mathbf{0.765}$$
- **Heuristic = 0.90, ML = 0.40**:
  $$\text{blended} = 0.45(0.90) + 0.55(0.40) = 0.405 + 0.220 = 0.625 \implies \text{final} = \max(0.90, 0.625) = \mathbf{0.900}$$

---

## Result Persistence & ScanResult Linkage

1. **`processed_emails`**:
   - Ingestion tracking record with state transitions: `received` $\to$ `fetching` $\to$ `fetched` $\to$ `analyzing` $\to$ `analyzed` $\to$ `completed`.
   - Stores denormalized `risk_score`, `classification`, and the full `signals` JSONB blob.
2. **`scan_results`**:
   - Shared analytical result table common to both on-demand manual mailbox scans (Phase 3) and autonomous real-time ingestion (RT-6).
   - Contains `verdict`, `risk_score`, `scan_details` (including top indicators, multi-engine results, and human-readable synthesized explanation).
   - Foreign key `processed_emails.scan_result_id` links the pipeline item directly to its threat artifact.

---

## Realtime Notification Hook

The `notify_email_processed` service dispatches real-time events upon completion:
- **Payload**:
  ```json
  {
    "processed_email_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "risk_score": 0.885,
    "classification": "phishing",
    "scan_result_id": "c71a3d90-12e4-47f2-8921-9bb410e5df11",
    "owner_user_id": "usr-example-123"
  }
  ```
- **Dispatches**:
  - Broadcasts to Supabase Realtime channel `realtime:emails` (event: `email_analyzed`) when client is active.
  - Persists an immutable record in `security_events` with `event_type='email_analyzed'` and `actor_type='system'` for compliance and audit logging.
