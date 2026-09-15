/**
 * ORG-5: in-app documentation content.
 *
 * PROVENANCE RULE: every example here is derived from a real artifact —
 * a fixture (backend/tests/data/…), an executed curl (recorded with its date
 * in src/docs/PROVENANCE.md), a suite-verified output, or a route/method
 * transcribed from backend/app/api/routes_*.py. Invented behavior or
 * invented outputs are forbidden; anything not executed is explicitly
 * marked "illustrative — not executed" in PROVENANCE.md.
 */

export type Audience = 'user' | 'org' | 'both';
export type MinRole = 'viewer' | 'analyst' | 'admin';

export type DocBlock =
  | { kind: 'text'; body: string }
  | { kind: 'list'; items: string[] }
  | { kind: 'code'; title?: string; lang?: string; code: string; provenance?: string }
  | { kind: 'diagram'; title?: string; code: string }
  | { kind: 'table'; headers: string[]; rows: string[][] };

export interface DocSection {
  id: string;
  title: string;
  audience: Audience;
  /** Role gate for org-audience sections (RoleGuard-style). */
  minRole?: MinRole;
  summary: string;
  body: DocBlock[];
}

export const DOC_SECTIONS: DocSection[] = [
  // ===========================================================================
  // 1. Overview & quickstart
  // ===========================================================================
  {
    id: 'overview-quickstart',
    title: 'Overview & Quickstart',
    audience: 'both',
    summary: 'What CYBERGUARD does, and the fastest path to value in each workspace type.',
    body: [
      {
        kind: 'text',
        body: 'CYBERGUARD is an AI-driven security operations platform with two workspace types. A personal workspace gives a single user mailbox-integrated email security; an organization workspace gives a SOC team gateway-fed threat analysis, Splunk-style log analysis, mail-server infrastructure connectors, and role-grouped notifications. The detection engines, scoring, and audit trail are shared; the ingestion surface and management plane differ.',
      },
      { kind: 'text', body: 'Personal workspace quickstart — connect, scan, review, release:' },
      {
        kind: 'list',
        items: [
          'Email Connectors → connect Gmail via OAuth (scopes: gmail.readonly + gmail.modify). Tokens are stored Fernet-encrypted; plaintext never returns.',
          'The scan endpoint pulls recent messages, normalizes them, and runs the engine stack on each — verdicts land on the message analysis view.',
          'Messages scored medium+ can be quarantined (moved to a CYBERGUARD label) automatically or on approval, per your enforcement policy.',
          'Review a quarantined message in the Quarantine Queue: release it, release-and-trust the sender, delete, or keep. Every action is written to Security History.',
        ],
      },
      { kind: 'text', body: 'Organization workspace quickstart — create org, issue key, call the gateway:' },
      {
        kind: 'list',
        items: [
          'Create your organization (you become admin; name conflicts are auto-salted, e.g. "Acme Corp-2").',
          'Org Settings → Create API key. The plaintext is shown exactly once; only its SHA-256 hash is stored.',
          'Point your mail pipeline or SIEM at the org gateway with the org_authorization header (actions: scan_email, scan_url, ingest_log).',
          'Watch the org dashboard and Live Log Analysis — ingested data is auto-analyzed, RLS-isolated per organization, and streamed in real time.',
        ],
      },
      {
        kind: 'code',
        title: 'First gateway call (executed — see PROVENANCE.md)',
        lang: 'bash',
        code: `curl -X POST http://localhost:8000/api/v1/org/<org_id>/gateway \\
  -H "org_authorization: cg_live_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{"action": "scan_email", "data": {"sender": "attacker@example.com",
       "subject": "Urgent: Verify your account", "body": "Click here to verify..."}}'`,
      },
    ],
  },

  // ===========================================================================
  // 2. Feature guides (x9, uniform skeleton)
  // ===========================================================================
  {
    id: 'guide-phishing',
    title: 'Phishing Analysis',
    audience: 'both',
    summary: 'Email phishing detection: heuristics + monotonic ML blend, verbose indicators, XAI explanation.',
    body: [
      { kind: 'text', body: 'What it detects: brand lookalike domains, urgency/suspension pressure language, IP-hosted links, credential-harvest patterns, spoofed senders, and ML-flagged phishing content. Engine: analyze_email_heuristics → hybrid blend (ML can raise, never lower, a heuristic score — property-tested: monotonic_blend_emails checked=300, lowered=0).' },
      { kind: 'text', body: 'Steps: POST the email to /api/v1/analysis/email (or the org gateway with action=scan_email); the pipeline persists an Event, scores it, synthesizes an XAI explanation with MITRE mapping, and creates an Alert with recommended actions.' },
      {
        kind: 'code',
        title: 'Example input (fixture: suite 3 / gateway smoke)',
        lang: 'json',
        code: `{
  "sender": "alerts@paypa1-security.com",
  "subject": "URGENT: Verify your account",
  "body": "Click http://185.220.101.7/login to verify your account immediately or it will be suspended."
}`,
        provenance: 'backend/scripts/run_all_tests.py [Suite 3]',
      },
      {
        kind: 'code',
        title: 'Example output (executed gateway scan, 2026-09-14)',
        lang: 'json',
        code: `{
  "module": "phishing", "threat_type": "phishing_email",
  "severity": "critical", "risk_score": 100,
  "indicators": [
    {"type": "lookalike_domain", "value": "paypa1-security.com", "severity": "critical",
     "description": "Sender domain 'paypa1-security.com' appears to imitate the official domain 'paypal.com'."},
    {"type": "urgency", "value": "verify", "severity": "high", "description": "Urgency keyword 'verify' found in the email."},
    {"type": "ip_url_in_body", "value": "http://185.220.101.7/login", "severity": "critical", "…": "…"}
  ],
  "explanation": "Critical Risk: … (MITRE ATT&CK T1566.002 Spearphishing Link)"
}`,
        provenance: 'executed curl @ 2026-09-14 (PROVENANCE.md)',
      },
      {
        kind: 'table',
        headers: ['Indicator', 'Severity', 'Meaning'],
        rows: [
          ['lookalike_domain', 'critical', 'Sender domain imitates a known brand'],
          ['urgency (urgent/verify/suspend)', 'high', 'Pressure language in subject/body'],
          ['ip_url_in_body', 'critical', 'Link points at a raw IP address'],
          ['ml_model', 'varies', 'XGBoost phishing-model probability band (url_xgb_v3.1 lineage)'],
        ],
      },
      { kind: 'text', body: 'Honest limitations: the online SMS-Spam corpus is out-of-domain for URL/credential-heavy email heuristics — the eval harness measured phishing_text precision 1.0 but recall 0.37 on that corpus (AUC 0.91) while synthetic email templates score high; SMS-shaped FPs are recorded, not silently fixed (eval_report.md findings).' },
    ],
  },
  {
    id: 'guide-url',
    title: 'URL Analysis',
    audience: 'both',
    summary: 'Reputation-aware malicious URL detection with the v3+ ML lineage and blended scoring.',
    body: [
      { kind: 'text', body: 'What it detects: raw-IP URLs, URL-shortener chains, random high-entropy paths, brand-in-path spoofing, and platform-hosted phishing (vercel.app, godaddysites.com, blogspot.com) that plain heuristics under-score. Model: url_xgb_v3 retrains on 50k top-1M benign URLs (10k tracking-augmented) + 50k real Phishing.Database URLs — benign domains with long tracking query strings now score < 0.05 phishing probability (eval_report.md, FIXED url_xgb_v3).' },
      {
        kind: 'code',
        title: 'Example input + executed output (2026-09-14)',
        lang: 'json',
        code: `POST /api/v1/analysis/url
{"url": "http://185.220.101.7/secure/login.php"}
→ {"severity": "high", "risk_score": 86, "…": "…"}`,
        provenance: 'executed curl @ 2026-09-14 (PROVENANCE.md)',
      },
      {
        kind: 'table',
        headers: ['Indicator', 'Severity', 'Meaning'],
        rows: [
          ['url_entropy', 'medium', 'High randomness in domain/path/query'],
          ['random_path_segment', 'medium', 'Machine-generated path segment'],
          ['ip_host', 'critical', 'Host is a raw IP address'],
          ['ml_model', 'varies', 'URL model probability (blended verdict)'],
        ],
      },
      { kind: 'text', body: 'Honest limitations: blended AUC 0.955 vs heuristic-only 0.766 (eval_report.md); residual FNs are recorded in the findings (e.g. lnk.ink/AQDO7 shortener at score 25, ml_model:critical) — the harness records findings instead of fixing them mid-run.' },
    ],
  },
  {
    id: 'guide-deepfake',
    title: 'Deepfake Detection',
    audience: 'both',
    summary: 'Media forensics: authenticity scoring for uploaded images/video/audio.',
    body: [
      { kind: 'text', body: 'What it detects: synthetic or manipulated media via the media-forensics engine (ELA-style artifacts + model scoring; audio LCNN gate in the ML stack). Upload to /api/v1/analysis/media as multipart/form-data; the file is stored, hashed, and analyzed.' },
      {
        kind: 'code',
        title: 'Example output shape (suite-verified)',
        lang: 'json',
        code: `{
  "authenticity_score": <0-100>,
  "verdict": "…",
  "storage_path": "…", "file_hash": "…"
}`,
        provenance: 'backend/scripts/run_all_tests.py [Suite 3] asserts authenticity_score + storage_path',
      },
      { kind: 'text', body: 'Honest limitations: eval_report.md media_forensics — precision 1.0, recall 0.935, AUC 0.935 (n=400); malicious mean 68.55 vs benign 46.00. Scores near the benign mean should be treated as inconclusive, not clean.' },
    ],
  },
  {
    id: 'guide-impersonation',
    title: 'Impersonation (BEC)',
    audience: 'both',
    summary: 'Executive/brand impersonation and wire-fraud message detection.',
    body: [
      { kind: 'text', body: 'What it detects: claimed-authority pressure (CFO/CEO/HR/IT), gift-card and wire-transfer requests, confidentiality + secrecy framing. Engine: analyze_impersonation_heuristics(message, claimed_identity).' },
      {
        kind: 'code',
        title: 'Example input (suite fixture) + output',
        lang: 'json',
        code: `POST /api/v1/analysis/impersonation
{"claimed_identity": "Chief Financial Officer",
 "message": "Urgent and confidential wire transfer request. Purchase gift cards and wire funds immediately."}
→ {"severity": "high", "risk_score": >= 60}`,
        provenance: 'backend/scripts/run_all_tests.py [Suite 3] asserts risk_score >= 60',
      },
      { kind: 'text', body: 'Honest limitations: the eval harness surfaced impersonation FNs — terse authority claims without transfer framing ("This is HR department. Email me the employee payroll list…") score 0. Recorded as findings in eval_report.md; org impersonation notifications fire only on listed indicator types (see the org guide).' },
    ],
  },
  {
    id: 'guide-log-analysis',
    title: 'Log Analysis',
    audience: 'both',
    summary: 'Personal paste-box analysis (auto-detects auth vs network) and the org Splunk-style live stream.',
    body: [
      { kind: 'text', body: 'Two surfaces: the personal Log Analysis page (paste a log; format auto-detected — auth-event vs network-flow JSON — detectors run analysis-only) and the org Live Log Analysis plane (gateway-ingested logs, auto-analyzed on arrival, manual analyst actions on the same plane). Log type detection is SHAPE-based, never a client-declared field.' },
      {
        kind: 'code',
        title: 'Example: impossible-travel auth log (fixture) → ATO verdict (executed)',
        lang: 'json',
        code: `{"data": {"events": [
  {"user": "alice", "ip": "10.0.1.45", "location": "New York, US", "status": "success", "timestamp": "…T09:00:00Z"},
  {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "status": "failed", "timestamp": "…T09:05:00Z"},
  {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "status": "success", "timestamp": "…T09:07:00Z"}]}}
→ {"log_type": "auth", "risk_score": 50, "severity": "medium",
   "indicators": [{"type": "impossible_travel", "severity": "critical",
     "description": "…'Moscow, RU' and 'New York, US' only 7 minutes apart."}]}
   → promoted to Event + Alert (module account_takeover)`,
        provenance: 'executed curl @ 2026-09-15 (PROVENANCE.md); detector = analyze_auth_log_heuristics',
      },
      {
        kind: 'table',
        headers: ['Indicator', 'Severity', 'Meaning'],
        rows: [
          ['impossible_travel', 'critical', 'Successive logins from distant locations'],
          ['new_device', 'medium', 'First-seen device for the user'],
          ['brute_force_window', 'high', 'Repeated failures then success'],
          ['app auth_failure pattern', 'medium', '"Failed password / authentication failure" in app logs'],
        ],
      },
      { kind: 'text', body: 'Honest limitations: network engine recall 0.666 at precision 1.0 on the eval corpus (per-flow heuristics are blind to low-and-slow beaconing — recorded finding); no LLM sits on the log-ingest path by design.' },
    ],
  },
  {
    id: 'guide-email-connectors',
    title: 'Email Connectors',
    audience: 'user',
    summary: 'Gmail OAuth connector with encrypted token vault and honest capability declaration.',
    body: [
      { kind: 'text', body: 'What it does: OAuth (own Google client), encrypted token storage (Fernet, CONNECTOR_TOKEN_KEY), automatic refresh, and mailbox scanning through the provider-neutral EmailProvider contract. Every provider declares its true capabilities via the capabilities property — the engine checks capabilities before any action and never guesses.' },
      { kind: 'text', body: 'Steps: Email Connectors page → Connect Gmail → consent → account appears with status connected. Scan runs list_messages → get_message → normalize → engine stack. Lifecycle statuses: connected | reauth_required | revoked | error.' },
      {
        kind: 'code',
        title: 'Provider contract (transcribed from email_providers/base.py)',
        lang: 'python',
        code: `class EmailProvider(Protocol):
    capabilities: dict                      # honest declaration — callers MUST consult
    async def authorize(*, redirect_uri, state) -> dict
    async def list_messages(access_token, max_results=50) -> list[dict]
    async def get_message(access_token, message_id) -> object
    async def quarantine_message(access_token, message_id, quarantine_label) -> dict
    async def release_message(access_token, message_id, quarantine_label) -> dict
    async def create_sender_rule(access_token, sender_email, target_label) -> dict
    async def get_profile(access_token) -> dict
    # … plus refresh_token, get_attachment, create_draft, send_message,
    #    modify_message, move_to_trash, delete_message, update/delete_sender_rule`,
        provenance: 'backend/app/services/email_providers/base.py (transcription)',
      },
      { kind: 'text', body: 'Honest limitations: Gmail in testing mode issues 7-day tokens (reconnect weekly — see Troubleshooting); provider-agnostic engine means unsupported verbs (e.g. sender rules on a provider without them) return the unsupported operation state instead of pretending success.' },
    ],
  },
  {
    id: 'guide-quarantine-senders',
    title: 'Quarantine & Sender Rules',
    audience: 'user',
    summary: 'Review queue: release, release-and-trust, delete, keep; blocked senders with expiry.',
    body: [
      { kind: 'text', body: 'What it does: quarantined messages (moved to the CYBERGUARD label) wait in the Quarantine Queue with their full verbose scan result. Actions: release, release-and-trust (adds the sender to your trust list — trusted senders never auto-enforce; scans still run, the action engine becomes recommend-only for them), delete (permanent, if enabled), keep. Blocked Senders manage Gmail filters with optional expiry.' },
      {
        kind: 'code',
        title: 'Routes (transcribed from routes_db.py)',
        lang: 'text',
        code: `GET    /api/v1/enforcement/quarantine                             # queue
POST   /api/v1/enforcement/quarantine/{item_id}/release
POST   /api/v1/enforcement/quarantine/{item_id}/release-and-trust
POST   /api/v1/enforcement/quarantine/{item_id}/delete
POST   /api/v1/enforcement/quarantine/{item_id}/keep
GET    /api/v1/enforcement/trusted-senders
GET    /api/v1/enforcement/blocked-senders
POST   /api/v1/enforcement/blocked-senders/{block_id}/release`,
        provenance: 'backend/app/api/routes_enforcement.py (transcription)',
      },
      { kind: 'text', body: 'Honest limitations: permanent delete requires the per-connector setting permanent_delete_enabled (default false); quarantine expiry hours are per-connector (NULL = manual release only). The FP-hardening marketing regression set (10 digest/newsletter/transactional emails) must stay ≤ medium and fail the corroboration gate — review-recommended, no provider write.' },
    ],
  },
  {
    id: 'guide-security-history',
    title: 'Security History & Audit',
    audience: 'user',
    summary: 'Permanent, owner-scoped record of real security events and provider operations.',
    body: [
      { kind: 'text', body: 'What it records: scan_verdict, quarantine, release, keep, delete, sender_block/release/expiry, connector_connect/disconnect/test, enforcement_decision, sender_trust/untrust. AI chat content is NEVER written here. Every row carries actor_type (user | system | scheduler) and operation_status from the five-state taxonomy below.' },
      {
        kind: 'code',
        title: 'Event write path (transcribed from security_history_service.record_event)',
        lang: 'python',
        code: `await record_event(db,
    owner_user_id=…, event_type="quarantine", actor_type="user",
    operation_status="success" | "failed" | "unsupported"
                            | "insufficient_scope" | "reauth_required",
    operation_detail=…)   # one row per real security event / provider operation`,
        provenance: 'backend/app/services/security_history_service.py (transcription)',
      },
      { kind: 'text', body: 'Honest limitations: history is append-only by design — corrections appear as new rows, never edits. Rows are RLS owner-scoped; a 0-row result for another user is isolation, not data loss (see Troubleshooting).' },
    ],
  },
  {
    id: 'guide-notifications',
    title: 'Notifications (per-user & org groups)',
    audience: 'both',
    summary: 'Phase 7 per-user event emails, plus ORG-4 role-grouped org notifications with min-role routing.',
    body: [
      { kind: 'text', body: 'Two distinct systems. Per-user (Phase 7): event emails go strictly to your notification_email — never to a connected mailbox; delivered DB-logged (demo-safe) or via optional SMTP. Org groups (ORG-4): the org registers MULTIPLE addresses grouped by role; each event type declares the minimum role group that receives it (min_role=admin → admins only; analyst → analysts+admins; viewer → everyone).' },
      {
        kind: 'code',
        title: 'Executed example: critical_log org notification (2026-09-15)',
        lang: 'json',
        code: `{
  "event_type": "critical_log",
  "subject": "[CRITICAL] Critical Security Event Detected",
  "status": "sent",
  "recipients": [
    {"role": "admin",   "email": "soc-admin-…@corp.example",  "status": "sent", "backend": "db_log"},
    {"role": "analyst", "email": "soc-analyst-…@corp.example","status": "sent", "backend": "db_log"}],
  "event_metadata": {"log_type": "auth", "severity": "critical", "risk_score": 90}
}`,
        provenance: 'executed curl @ 2026-09-15 (PROVENANCE.md)',
      },
      {
        kind: 'table',
        headers: ['Org event type', 'Default min_role', 'Trigger'],
        rows: [
          ['server_down', 'analyst', 'Fetch fails on a connected mail server'],
          ['mail_server_down', 'analyst', 'Mail-server connect fails (bad/incomplete credentials)'],
          ['critical_log', 'analyst', 'Gateway log ingest scores medium+'],
          ['impersonation', 'admin', 'Gateway scan finds lookalike/spoof indicators'],
        ],
      },
      { kind: 'text', body: 'Honest limitations: a disabled event type is a silent no-op (no log row); delivery "sent" with backend db_log means rendered-and-recorded, not SMTP-transmitted.' },
    ],
  },

  // ===========================================================================
  // 3. Scanning architecture
  // ===========================================================================
  {
    id: 'scanning-architecture',
    title: 'Scanning Architecture',
    audience: 'both',
    summary: 'Pipeline, provider contract, and tenancy/RLS — the three load-bearing diagrams.',
    body: [
      {
        kind: 'diagram',
        title: '(a) Scan → verdict → enforcement pipeline',
        code: ` ingested artifact (email / URL / log / media)
        │
        ▼
  normalize  ──►  engine stack
        │             ├─ heuristic detectors  (per-module indicator sets)
        │             └─ ML models            (url_xgb_v3.1, phishing, ATO, …)
        │                  monotonic blend: ML can RAISE, never LOWER
        ▼
  severity bands  (safe | low | medium | high | critical)
        ▼
  verbose explanation  (XAI + MITRE ATT&CK mapping; LLM when available,
        │               deterministic synthesized fallback when not)
        ▼
  enforcement  ── corroboration gate: auto-provider-writes require
        │          >=2 engines in high+ bands; otherwise review_recommended
        ▼
  history / audit  (security_events + audit_logs, append-only)`,
      },
      {
        kind: 'diagram',
        title: '(b) EmailProvider contract + honest registry',
        code: ` action_engine / mail_scanner / scheduler
        │  (engine NEVER imports Gmail-specific code)
        ▼
 EmailProvider Protocol  (email_providers/base.py)
        │  capabilities: read_messages, read_attachments, modify_labels,
        │                quarantine, trash, permanent_delete, sender_rules, send_mail
        │  callers MUST consult capabilities before every verb
        ▼
 provider registry: gmail ── capabilities honored; unsupported verbs return
                    the "unsupported" operation state — never fake success`,
      },
      {
        kind: 'diagram',
        title: '(c) Tenancy & row-level security',
        code: ` request ──► bearer token verified ──► app.user_id GUC stamped
        │                                     (per-transaction, after_begin)
        ▼
 PostgreSQL RLS  (schema: cyberguard)
   role cyberguard_api: NOBYPASSRLS — every query is policy-filtered
   personal rows: owner_user_id = app.user_id
   org rows:      membership via cyberguard.org_member_role()
                  (SECURITY DEFINER — recursion-safe, owner fallback)
        ▼
 cross-tenant read = 0 rows  (isolation, not emptiness)`,
      },
      { kind: 'text', body: 'Corroboration-gated enforcement (FP-hardening): the marketing regression set (10 realistic digest/newsletter/transactional emails) must stay ≤ medium and fail the corroboration gate, while brand-lookalike / IP-host / platform-hosted phishing must trip it (≥2 engines high+) and land on the auto-quarantine path (eval_report.md).' },
    ],
  },

  // ===========================================================================
  // 4. Org guide
  // ===========================================================================
  {
    id: 'org-guide',
    title: 'Organization Guide',
    audience: 'org',
    minRole: 'viewer',
    summary: 'Gateway, API keys, roles, mail-server connectors, log analysis, notification groups.',
    body: [
      { kind: 'text', body: 'The org plane is server-to-server: data arrives via the gateway and mail-server connectors — there are no manual paste-boxes.' },
      {
        kind: 'code',
        title: 'Gateway (executed 2026-09-14: critical, risk 100)',
        lang: 'bash',
        code: `curl -X POST http://localhost:8000/api/v1/org/<org_id>/gateway \\
  -H "org_authorization: cg_live_…" -H "Content-Type: application/json" \\
  -d '{"action": "scan_email", "data": {"sender": "alerts@paypa1-security.com",
       "subject": "URGENT: Verify your account", "body": "Click http://185.220.101.7/login …"}}'

# actions: scan_email | scan_url | ingest_log
# 401 = missing/invalid/expired/revoked key · 403 = key belongs to another org`,
        provenance: 'executed curl @ 2026-09-14 (PROVENANCE.md)',
      },
      { kind: 'text', body: 'Key lifecycle: create (plaintext shown exactly once — only the SHA-256 hash is stored, key_prefix kept for display), rotate (create a new key, then revoke the old), revoke (integrations stop immediately). Keys authenticate only the org they belong to.' },
      {
        kind: 'table',
        headers: ['Role', 'Dashboard', 'Gateway/ingest', 'API keys', 'Members', 'Sensitive settings'],
        rows: [
          ['admin', 'full', 'manage', 'create/revoke', 'manage', 'read + write'],
          ['analyst', 'read + analyze', 'ingest via key', '—', 'read roster', 'read'],
          ['viewer', 'read-only', '—', '—', 'read roster', 'blocked (RLS + API)'],
        ],
      },
      { kind: 'text', body: 'Mail-server connectors (ORG-3): register Google Workspace (service account + delegated user), Microsoft 365 (client id/secret/tenant), or IMAP/SMTP. Credentials are validated per provider schema and Fernet-encrypted at rest — never returned. Disconnect is graceful (mail server keeps running, credentials retained); delete removes credentials and that server’s log stream. Logs are grouped BY server, each server has its own settings (scan_interval_seconds, quarantine_enabled, auto_block_malicious_senders, quarantine_expiry_hours).' },
      { kind: 'text', body: 'Live Log Analysis (ORG-2): logs auto-detect as auth / network / app by payload shape, run the matching detector with no LLM on the ingest path, and medium+ findings are promoted to the alert plane. Analysts take manual actions per row (block_ip, revoke_session, isolate_host, escalate_incident, mark_safe) — recorded with actor + audit entry; real enforcement targets arrive with connector integrations.' },
      { kind: 'text', body: 'Notification groups (ORG-4): register multiple addresses grouped by role; per-event min_role routes who is paged. Triggers are wired to real events: mail-server connect failure, connected-server fetch failure, medium+ log ingest, and impersonation indicators. Delivery reuses the Phase 7 backend (db_log by default, best-effort SMTP).' },
      { kind: 'text', body: 'Realtime: org dashboards subscribe via Supabase postgres_changes with filter organization_id=eq.<org_id>; a polling fallback covers setups without realtime.' },
    ],
  },

  // ===========================================================================
  // 5. API reference (transcribed — check script verifies ⊆ real routes)
  // ===========================================================================
  {
    id: 'api-reference',
    title: 'API Reference',
    audience: 'both',
    summary: 'Curated route table, transcribed from the real routers. Every row is verified against backend/app/api/routes_*.py by the docs check script.',
    body: [
      {
        kind: 'table',
        headers: ['Method', 'Path', 'Auth', 'Purpose'],
        rows: [
          ['GET', '/api/v1/health', 'none', 'Liveness + database connectivity'],
          ['POST', '/api/v1/auth/signup', 'none', 'Create account with unique username'],
          ['POST', '/api/v1/auth/signin', 'none', 'Password sign-in (username or email)'],
          ['GET', '/api/v1/auth/me', 'bearer', 'Identity, tenant context, org flag'],
          ['POST', '/api/v1/auth/switch-org', 'bearer', 'Switch active workspace'],
          ['POST', '/api/v1/analysis/email', 'bearer', 'Full phishing pipeline'],
          ['POST', '/api/v1/analysis/url', 'bearer', 'Full URL pipeline'],
          ['POST', '/api/v1/analysis/impersonation', 'bearer', 'BEC/impersonation pipeline'],
          ['POST', '/api/v1/analysis/account-takeover', 'bearer', 'Auth-log ATO pipeline'],
          ['POST', '/api/v1/analysis/network', 'bearer', 'Network/API-abuse pipeline'],
          ['POST', '/api/v1/analysis/media', 'bearer', 'Media forensics (multipart)'],
          ['GET', '/api/v1/alerts', 'bearer', 'Alert list (tenant-scoped)'],
          ['GET', '/api/v1/dashboard/summary', 'bearer', 'Personal dashboard metrics'],
          ['POST', '/api/v1/connectors/gmail/authorize', 'bearer', 'Start Gmail OAuth'],
          ['GET', '/api/v1/connectors/gmail/callback', 'none (state)', 'OAuth callback (single-use state)'],
          ['POST', '/api/v1/connectors/{id}/scan', 'bearer', 'Scan connected mailbox'],
          ['GET', '/api/v1/enforcement/quarantine', 'bearer', 'Quarantine queue'],
          ['POST', '/api/v1/enforcement/quarantine/{item_id}/release', 'bearer', 'Release message'],
          ['POST', '/api/v1/enforcement/quarantine/{item_id}/release-and-trust', 'bearer', 'Release + trust sender'],
          ['GET', '/api/v1/enforcement/blocked-senders', 'bearer', 'Blocked sender rules'],
          ['GET', '/api/v1/security-history', 'bearer', 'Permanent security history'],
          ['GET', '/api/v1/notifications', 'bearer', 'Per-user notification log'],
          ['POST', '/api/v1/orgs', 'bearer', 'Create organization (salted name)'],
          ['POST', '/api/v1/orgs/{org_id}/api-keys', 'org admin', 'Create API key (plaintext once)'],
          ['GET', '/api/v1/orgs/{org_id}/api-keys', 'org admin', 'List keys (prefix only)'],
          ['DELETE', '/api/v1/orgs/{org_id}/api-keys/{key_id}', 'org admin', 'Revoke key'],
          ['POST', '/api/v1/org/{org_id}/gateway', 'api key', 'scan_email | scan_url | ingest_log'],
          ['POST', '/api/v1/org/{org_id}/logs/ingest', 'api key', 'Ingest + auto-analyze log'],
          ['GET', '/api/v1/org/{org_id}/logs/stream', 'org viewer+', 'Latest ingested logs'],
          ['POST', '/api/v1/org/{org_id}/logs/{log_id}/action', 'org analyst+', 'Manual analyst action'],
          ['GET', '/api/v1/org/{org_id}/dashboard/summary', 'org analyst+', 'Org headline metrics'],
          ['GET', '/api/v1/org/{org_id}/dashboard/{feature}', 'org viewer+', 'Verbose feature feed'],
          ['POST', '/api/v1/org/{org_id}/mail-servers', 'org admin', 'Register mail server'],
          ['POST', '/api/v1/org/{org_id}/mail-servers/{id}/connect', 'org admin', 'Connect / rotate credentials'],
          ['POST', '/api/v1/org/{org_id}/mail-servers/{id}/disconnect', 'org admin', 'Graceful disconnect'],
          ['GET', '/api/v1/org/{org_id}/mail-servers/{id}/logs', 'org analyst+', 'Per-server log stream'],
          ['GET', '/api/v1/org/{org_id}/mail-servers/{id}/settings', 'org analyst+', 'Per-server settings'],
          ['PUT', '/api/v1/org/{org_id}/mail-servers/{id}/settings', 'org admin', 'Update per-server settings'],
          ['GET', '/api/v1/org/{org_id}/notifications/emails', 'org analyst+', 'Registered recipients'],
          ['POST', '/api/v1/org/{org_id}/notifications/emails', 'org admin', 'Register recipient'],
          ['GET', '/api/v1/org/{org_id}/notifications/settings', 'org analyst+', 'Event routing (min_role)'],
          ['PUT', '/api/v1/org/{org_id}/notifications/settings/{event_type}', 'org admin', 'Update routing'],
          ['GET', '/api/v1/org/{org_id}/notifications/logs', 'org analyst+', 'Delivery history'],
        ],
      },
      { kind: 'text', body: 'The 501 "coming soon" envelope marks still-frozen features (e.g. the legacy /organizations router while ORG_ENABLED is false). Error envelope: {"error", "message", "details?"} with proper status codes — 401 unauthorized, 403 permission_denied, 404 not_found, 409 conflict, 400 validation_error.' },
    ],
  },

  // ===========================================================================
  // 6. Failure taxonomy
  // ===========================================================================
  {
    id: 'failure-taxonomy',
    title: 'Failure Taxonomy',
    audience: 'both',
    summary: 'Five operation states, how the UI renders each, and why fake actions are banned.',
    body: [
      { kind: 'text', body: 'Every provider operation and security event resolves to exactly one of five operation states (security_history_service). The UI renders each distinctly — nothing is silently swallowed and nothing pretends success.' },
      {
        kind: 'table',
        headers: ['State', 'Meaning', 'UI rendering'],
        rows: [
          ['success', 'The operation actually completed', 'Confirmation + history row (actor: user/system/scheduler)'],
          ['failed', 'Provider/engine call failed', 'Error toast with the sanitized message; history row with operation_detail'],
          ['unsupported', 'The provider cannot do this at all', 'Disabled/badged action — surfaced from capabilities, not attempted'],
          ['insufficient_scope', 'Connected with missing OAuth scopes', 'Banner pointing at reconnect with broader scopes (eval-verified: provider 403 maps here)'],
          ['reauth_required', 'Token expired/revoked', 'Reconnect banner on the connector; operations block until re-auth'],
        ],
      },
      { kind: 'text', body: 'Why fake actions are banned: the action engine consults the provider’s declared capabilities before every verb; a capability the provider lacks returns unsupported instead of a simulated success, and error payloads are mapped to the ProviderErrorClass taxonomy (reauth_required, insufficient_scope, rate_limited, failed) — raw provider payloads never reach the UI. The org mail-connector transport follows the same rule: simulated results are flagged mode: simulated in logs and responses.' },
      { kind: 'text', body: 'Gateway/log errors: unknown action → 400; missing/invalid key → 401; cross-org key → 403. Dashboard "0 rows" for a cross-org user is RLS isolation working (see Troubleshooting).' },
    ],
  },

  // ===========================================================================
  // 7. Troubleshooting
  // ===========================================================================
  {
    id: 'troubleshooting',
    title: 'Troubleshooting',
    audience: 'both',
    summary: 'Real incidents from the runbook, eval findings, and the RLS baseline — with remedies.',
    body: [
      { kind: 'text', body: 'Gmail 403 — API not enabled / test users: the Google account must have the Gmail API enabled and the account added as a test user on the OAuth client while the app is in testing. The connector surfaces this as insufficient_scope/failed — check the connector’s last_error before retrying.' },
      { kind: 'text', body: '7-day testing-token expiry: Google issues 7-day refresh tokens while the OAuth client is in testing mode. Expect weekly reconnects (status reauth_required) until the client is published.' },
      { kind: 'text', body: 'reauth_required vs insufficient_scope: reauth = credentials expired/revoked → reconnect; scope = connected but missing a permission → reconnect with broader scopes. Both are visible on the Email Connectors page and in Security History.' },
      { kind: 'text', body: 'Demo-token fallback: tokens containing "demo"/"test" bypass Supabase verification for local scripts (get_current_user fallback) and map to a JIT user row. If your identity looks wrong in a local demo, you are probably holding a demo-shaped token.' },
      { kind: 'text', body: 'RLS cross-user denial: with the cyberguard_api role (NOBYPASSRLS), another user’s rows return 0 rows — an empty list is isolation, not data loss. Verify by checking the Security History of the owning account or querying under the service role.' },
      { kind: 'text', body: 'CONNECTOR_TOKEN_KEY changed: stored tokens/credentials cannot be decrypted ("Stored connector token cannot be decrypted"). Remedy: reconnect the mailbox / re-enter mail-server credentials. The org expiry scheduler logs this per affected block row rather than crashing.' },
      { kind: 'text', body: 'All LLM providers down: explanations fall back to the deterministic synthesized path (heuristic + MITRE) — analysis, scoring, and enforcement continue uninterrupted; only the prose degrades. Rate-limited keys rotate and auto-recover after cooldown.' },
    ],
  },
];

/** Flat anchor id list — the docs page and the check script both use this. */
export const DOC_IDS: string[] = DOC_SECTIONS.map((s) => s.id);
