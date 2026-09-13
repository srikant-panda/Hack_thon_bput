# Evaluation Harness (pytest)

A real pytest-based evaluation harness in `backend/tests/` that stress-tests
every detection engine at scale — hundreds to thousands of cases per engine —
using online-fetched datasets (cached + provenance-tracked) with deterministic
synthetic generators as a mandatory fallback. The harness measures the engines
as shipped; per the evaluation rules it **records** findings instead of fixing
app code.

## Running

```bash
cd backend

uv run pytest tests -v                 # default scale (~500/engine, ~80s)
uv run pytest tests --full -v          # 5x scale
uv run pytest tests --fetch -v         # force re-download of online datasets
uv run pytest tests --offline -v       # synthetic only — never touch the network
uv run pytest "tests/test_eval_media.py" -v   # a single engine
```

Requirements: the dev deps `pytest` / `pytest-asyncio` (already in
`pyproject.toml` `[dependency-groups] dev`). The old regression suite
(`scripts/run_all_tests.py`) is **not** collected by pytest (`norecursedirs`)
and must stay green independently.

## Data flow

1. **Online fetch (once):** `tests/datakit.py:fetch_or_cache` downloads each
   dataset into `tests/data/cache/` (gitignored) and records provenance —
   source URL, HTTP status, row count, SHA256, fetch date — into
   `tests/data/PROVENANCE.md` and the session report.
   - `sms_spam`: SMS Spam Collection TSV (justmarkham/DAT8 raw) — 5572 rows.
   - `phishing_urls`: OpenPhish feed (plain-text phishing URL list) — live
     phishing URLs, fetched and cached.
2. **Cache:** subsequent runs read the cache (mode `cache`).
3. **Synthetic fallback (mandatory):** if `--offline` or every URL fails,
   seeded deterministic generators produce the dataset so the suite always
   runs offline at the venue.

Synthetic generators (all expose `(payload, expected_label, expected_band_hint)`):
emails ≥1000 (phishing/benign templates × domains × payloads), URLs ≥2000
(malicious patterns + benign sampled from `ml/data/url_whitelist/top1m.txt`),
images ≥400 (PIL benign vs splice/copy-move/recompress), audio ≥400 WAV
(tone vs spoof-like formant bursts), auth sessions ≥2000 (brute-force, spray,
impossible travel, new-device), network flows ≥2000 (beaconing, exfil, bad
ports), impersonation pairs ≥600.

## What is measured

Per engine (`test_eval_phishing.py`, `test_eval_url.py`, `test_eval_media.py`,
`test_eval_impersonation.py`, `test_eval_ato.py`, `test_eval_network.py`),
direct service calls batched over the dataset:

- Precision / Recall / F1 (binary at the positive threshold),
- ROC AUC (threshold-free headline metric),
- Band separation: malicious mean score − benign mean score + Mann-Whitney U
  p-value,
- Adaptive threshold where an engine's score range makes a fixed 50
  inappropriate (midpoint of class means; the threshold used is reported),
- Top FP/FN payloads with snippets + scores + indicators recorded as findings.

Property tests (`test_eval_properties.py`): the monotonic blend (ML may raise,
never lower — verified over 1000 cases), severity-band monotonicity, and
`split_ml_indicator` round-trip on 1000 synthetic indicator sets.

HTTP (`test_eval_api_http.py`, `http` marker): sampled `/analysis/*` requests
through the ASGI client with the REAL demo-token auth path; latency
p50/p95/p99 recorded per endpoint.

Honesty (`test_eval_honesty.py`): mocked provider 403 →
`operation_status=insufficient_scope` in both the ScanResult and the
security event (never success); out-of-scope assistant input refused without
an LLM call.

## Reports

At session end: `tests/reports/eval_report.md` + `.json` — per-engine metric
table, property-test results, HTTP latency percentiles, provenance table,
scale used, git tip, and the **Findings** list (bugs the harness discovered;
app code is deliberately never fixed from inside the harness).

## Known findings (current run)

1. **URL v2 XGBoost flags benign top-1m domains** (paypal.com, google.com,
   wikipedia.org) at phishing probability ~0.76 — blended pipeline FPs on
   benign domains dominate; heuristic-only URL scoring avoids them.
2. **Real OpenPhish URLs hosted on legitimate platforms** (vercel.app,
   godaddysites.com) are structurally plain: heuristic-only AUC ~0.77 while
   the ML model detects them (blended AUC 0.97) — validates the hybrid design.
3. **Per-flow network heuristics cannot detect low-and-slow beaconing**
   (regular 60s callbacks carry no per-flow weight) — recall ceiling ~2/3
   on the mixed dataset; cross-flow interval analysis would be needed.
4. **Phishing-text recall is corpus-limited**: the SMS corpus is
   out-of-domain for URL/credential-heavy email heuristics (precision stays
   1.0; synthetic email templates score high).
