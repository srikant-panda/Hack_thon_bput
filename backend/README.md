# 🛡️ CYBERGUARD — Backend Engine & API Architecture

FastAPI backend for **CYBERGUARD**: an autonomous Security Operations Center (SOC) and SOAR platform powering multi-vector threat ingestion, hybrid ML/heuristic detection, Explainable AI (XAI) via distributed OpenRouter key rotation, and automated response orchestration.

---

## ⚡ Core Systems & Architecture

```text
Incoming Ingestion Payload (Email / URL / Message / ATO / Network / Media)
                             │
                             ▼
               ┌───────────────────────────┐
               │ Heuristic Detection Engine │
               │   (Rule-based telemetry)  │
               └─────────────┬─────────────┘
                             │
                             ▼
               ┌───────────────────────────┐
               │ ML Model Scoring Pipeline │
               │  (XGBoost / CNN Models)   │
               └─────────────┬─────────────┘
                             │
                             ▼
               ┌───────────────────────────┐
               │   Risk Score Synthesizer  │
               │ (Risk: 0-100 & Severity)  │
               └─────────────┬─────────────┘
                             │
                             ▼
         ┌───────────────────────────────────────┐
         │ OpenRouter Multi-Key Rotator Engine   │
         │ - Distributed Round-Robin Load Balancer│
         │ - Active Circuit Breaker (429/401/402)│
         │ - Background Key Health Check Recovery│
         └───────────────────┬───────────────────┘
                             │
                             ▼
               ┌───────────────────────────┐
               │ Explainable AI (XAI) Intel│
               │  (MITRE ATT&CK & Actions) │
               └─────────────┬─────────────┘
                             │
                             ▼
         ┌───────────────────────────────────────┐
         │ SQLAlchemy 2.0 Async Multi-Tenancy    │
         │ - Single-User Personal Workspace      │
         │ - Organization-scoped Team SOC RBAC   │
         └───────────────────────────────────────┘
```

---

## 🔄 Multi-Provider Distributed LLM Engine & Key Rotation

CYBERGUARD incorporates a production-grade multi-provider LLM orchestration engine in [`backend/app/ai/llm_client.py`](app/ai/llm_client.py) and [`backend/app/ai/key_rotator.py`](app/ai/key_rotator.py):

1. **Multi-Provider Support**: Supports **Groq** (ultra-fast Llama 3.3 70B & 8B), **Google Gemini** (Gemini 2.0 Flash & 1.5 Flash), and **OpenRouter** (OpenAI and Anthropic are excluded by design).
2. **Distributed Load Balancing**: Instead of hammering a single provider or key, requests cycle evenly across all healthy configured providers using round-robin distribution.
3. **Key Pool per Provider**: Every provider supports up to a configurable maximum of keys (default: 10 via `GROQ_MAX_KEYS`, `GEMINI_MAX_KEYS`, `OPENROUTER_MAX_KEYS`). Keys can be provided as comma-separated lists (`GROQ_API_KEYS=k1,k2`) or numbered environment variables (`GROQ_API_KEY_1`, etc.).
4. **Automatic Provider Failover**: If a provider or its keys encounter rate limits (`429`), auth errors (`401/402/403`), or network downtime, the system automatically marks the key down with a cooldown and immediately jumps to the next healthy provider without failing the user's request.
5. **Free-Time Health Probes & Re-release**: A background asyncio monitor periodically probes downed keys across all providers in the background. Once a key recovers or its cooldown expires, it is automatically re-instated into the active pool.
6. **Resilient Startup & Clean Logging**: The backend never crashes or refuses to start if keys are missing. During startup, the engine cleanly logs which providers are configured vs. not defined.
7. **Zero-Downtime Deterministic Heuristic Fallback**: If no keys are defined across any provider, or if all external providers temporarily experience outages, the system seamlessly generates high-quality deterministic forensic heuristic explanations and MITRE ATT&CK technique mappings.

---

## 🏢 Multi-Tenancy & Workspace Isolation

CYBERGUARD supports dual operational paradigms out of the box:

* **Single-User Personal Workspace**: Users authenticating without an explicit organization membership are automatically assigned an isolated Personal Workspace. All ingested alerts, logs, and incidents are scoped exclusively to their user ID.
* **Team SOC RBAC**: Full multi-tenant organizational structure with Role-Based Access Control (`admin`, `analyst`, `viewer`), cross-analyst incident assignments, and shared playbook response actions.

---

## 📁 Endpoints Summary (`/api/v1`)

| Router | Path Prefix | Responsibilities |
|---|---|---|
| **Health** | `/health` | Liveness check, database connectivity, storage status |
| **Analysis** | `/analysis/*` | Threat analyzers (email, url, impersonation, account-takeover, network, media) |
| **Events** | `/events/*` | Raw telemetry ingestion stream |
| **Alerts** | `/alerts` | Alert queries, MITRE mappings, status lifecycle transitions |
| **Incidents** | `/incidents` | SOC incident creation, severity escalation, assignment |
| **Responses** | `/responses` | SOAR response playbook catalog and execution engine |
| **Dashboard** | `/dashboard` | Executive SOC metrics, risk score distributions, attack trends |
| **Organizations**| `/organizations` | Multi-tenant organization and member management |
| **Audit** | `/audit` | Immutable audit log of all analyst actions and response executions |
| **Assistant** | `/assistant` | Contextual SOC AI assistant query interface |

---

## 🛠️ Local Development & Running Tests

### 1. Environment Configuration

```bash
cd backend
cp .env.example .env
```

Ensure `DATABASE_URL` and your `OPENROUTER_API_KEY`(s) are specified.

### 2. Fast Setup with `uv`

```bash
# Create virtualenv and install dependencies
uv venv
source .venv/bin/activate
uv pip install -e .
```

### 3. Run the Complete Test Suite

CYBERGUARD features a comprehensive integration test suite covering all 4 critical operational domains:

```bash
uv run python scripts/run_all_tests.py
```

**Verifies:**
* **Suite 1**: Database tables, migrations, personal workspace auto-creation, and organization RBAC.
* **Suite 2**: 6 Threat Detection engines, risk calculation, and SOAR response playbooks.
* **Suite 3**: End-to-end API HTTP routes with mock / live Supabase Auth headers.
* **Suite 4**: Distributed API key rotation, circuit breaker isolation, and background cooldown re-release.

### 4. Run Development Server

```bash
uv run uvicorn app.main:app --reload --port 8000
```
Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

