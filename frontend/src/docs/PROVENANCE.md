# PROVENANCE — docs content examples

Every example in `frontend/src/docs/content.ts` traces to a real artifact.
Executed probes ran against the local stack (`uvicorn` on 127.0.0.1:8000,
Supabase Postgres at migration `0012`) on **2026-09-15**; raw outputs were
captured to `/tmp/org5_probes/log.txt` during authoring.

## Executed curls (all executed 2026-09-15, outputs captured)

| Docs example | Probe | Result |
| --- | --- | --- |
| overview-quickstart: gateway call shape | `POST /api/v1/org/{org_id}/gateway` (scan_email, paypa1 payload) | `status: success`, severity critical |
| guide-phishing: example input + output (risk 100, lookalike_domain, ip_url_in_body) | `POST /api/v1/analysis/email` | severity critical, risk **100** |
| guide-url: example input + output | `POST /api/v1/analysis/url` (185.220.101.7 payload) | severity critical, risk **86** |
| guide-impersonation: example input + output | `POST /api/v1/analysis/impersonation` (CFO gift-card payload) | severity critical, risk **100** |
| guide-log-analysis: org ingest (impossible travel, risk 50, medium) | `POST /api/v1/org/{org_id}/logs/ingest` (3-event auth log) | `log_type: auth`, risk **50**, promoted to alert |
| org-guide: gateway curl + 401/403 contract | `POST /api/v1/org/{org_id}/gateway` + unauthenticated probe | success / **401** |
| org-guide: key lifecycle | `POST /api/v1/orgs/{org_id}/api-keys` | plaintext returned once, `key_prefix` stored |
| guide-notifications: critical_log org notification JSON | executed 2026-09-15 (ORG-4 report capture, same pipeline) | recipients admin+analyst, `backend: db_log` |
| api-reference rows | route-table transcription verified by `frontend/scripts/check-docs.mjs` | **43 rows ⊆ real routes — ALL PASS** |
| summary metrics (2 scans / 2 threats) | `GET /api/v1/org/{org_id}/dashboard/summary` after the two probes above | `total_scans: 2, threats_detected: 2` |

## Suite-verified shapes (asserted by `backend/scripts/run_all_tests.py`, not a single curl)

- guide-deepfake output shape (`authenticity_score`, `storage_path`, `file_hash`) — Suite 3 media assertions.
- guide-email-connectors: provider contract transcription — `backend/app/services/email_providers/base.py`.
- guide-quarantine-senders routes — `backend/app/api/routes_enforcement.py` (transcription; check-script verified).
- guide-security-history: `record_event` signature — `backend/app/services/security_history_service.py`.
- failure-taxonomy five states — `SecurityEvent.operation_status` values (`success | failed | unsupported | insufficient_scope | reauth_required`) and `ProviderErrorClass` in `email_providers/base.py`.

## Fixture / report citations

- FP-hardening marketing regression set (10 emails, "≤ medium, fails corroboration gate") and phishing positive control — `backend/tests/reports/eval_report.md` findings + `backend/tests/data/synthetic/marketing_emails.json`.
- Monotonic blend property checks (emails 300 / urls 1000, 0 violations) — `eval_report.md` property tests.
- Engine metrics quoted (phishing_text P1.0/R0.37/AUC0.91, url blended AUC 0.955 vs heuristic 0.766, media AUC 0.935, network P1.0/R0.666) — `eval_report.md` per-engine table.
- url_xgb_v3 fix narrative (benign top-1M + tracking augmentation, FN list incl. `lnk.ink/AQDO7`) — `eval_report.md` findings.
- impersonation FN examples ("This is HR department…") — `eval_report.md` findings.
- Troubleshooting incidents (Gmail 403/test-users, 7-day testing tokens, demo-token fallback, RLS 0-rows, CONNECTOR_TOKEN_KEY rotation, LLM fallback) — `backend/docs/RUNBOOK.md`, `app/core/security.py` (demo-token fallback), `app/core/crypto.py` (decrypt error), `app/ai/` key rotator behavior.

## Illustrative — not executed

- The scanning-architecture ASCII diagrams are structural transcriptions of
  the pipeline in code (`routes_analysis._run_analysis_pipeline`,
  `action_engine` corroboration gate, `email_providers/base.py`, RLS wiring
  in `app/db/session.py` + migration `0008/0012`) — they describe real
  components but are diagrams, not captured output.
- The docs-check-verified route table is transcribed from source, verified
  mechanically; paths were not all curl-exercised (destructive verbs —
  revoke/delete/disconnect — are intentionally not executed against the live
  org in this probe run).
