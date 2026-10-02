# Demo Server — Production-grade CyberGuard Traffic Generator & Campaign Simulator

Standalone tool that generates realistic security-event traffic and replays
multi-stage attack campaigns against the [CyberGuard](../README.md) project
gateway (`POST /api/v1/p/{slug}/gateway`). It is the load-and-demo arm of
CyberGuard: everything it ships flows through the real analysis pipeline and
lands in the org dashboard as events, alerts, and closed-loop
auto-enforcement.

Zero CyberGuard backend/frontend imports — it consumes the gateway exactly
like an external integration would, over Bearer-key auth. Built on
pydantic-settings (strict env/`.env` configuration) and a Typer CLI, in a
`src/`-layout package.

## Features

- **Realistic attack campaigns** — four built-in multi-stage campaigns
  (credential stuffing, C2 beacon waves, exfiltration spikes, full APT
  lifecycle) using verified trigger rules from the analyzers.
- **Time-aware payloads** — stage delays with `--timescale` acceleration,
  attacker-IP parameterization, jittered continuous traffic generation.
- **Gateway integration** — Bearer master-key auth, exponential-backoff
  retries on 5xx/transport errors only (4xx never retried), strict
  env/`.env` configuration with fail-fast startup errors.
- **Detailed reporting** — SQLite store of every attempt (request, response,
  latency, error), per-run JSON campaign reports, latency percentiles and
  status mixes via the metrics endpoint, window replay.
- **HTTP control API** — start/stop/status background traffic jobs, query
  metrics and stored responses (port 8020).

## Setup

Prerequisites: [uv](https://docs.astral.sh/uv/) and a running CyberGuard
stack (backend on `:8000`; see `backend/docs/RUNBOOK.md`).

```bash
cd demo-server-project
uv sync                       # install dependencies into .venv (or: pip install -e .)
cp .env.example .env          # then edit .env (see Configuration below)
```

Create a project + **master API key** once in the CyberGuard frontend
(org workspace → **Project Settings → API Keys**). The plaintext key
is shown **once** — paste it into `.env` immediately, and note
the **project slug** shown next to the gateway row.

## Configuration

All values come from the environment or a local `.env` (gitignored). Lookup
order per variable: shell environment (empty exports ignored) → `.env` in
the working directory → `.env` in the project root → built-in default.
Required values missing or contradictory fail fast at startup with a clear
message. Legacy `CYBERGUARD_*` aliases are still accepted; the primary name
wins when both are set.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PROJECT_SLUG` | yes | — | CyberGuard project slug to ship as (alias `CYBERGUARD_PROJECT_SLUG`) |
| `MASTER_API_KEY` | one of two | — | gateway master key, inline (alias `CYBERGUARD_MASTER_KEY`) |
| `KEY_FILE` | one of two | — | file holding the gateway key — preferred on shared machines (alias `CYBERGUARD_KEY_FILE`) |
| `GATEWAY_URL` | no | `http://localhost:8000/api/v1` | backend API base URL; the tool ships to `{GATEWAY_URL}/p/{slug}/gateway` (alias `CYBERGUARD_GATEWAY_URL`) |
| `DEFAULT_RATE` | no | `10` | default traffic rate for `generate` and `/traffic/start` (events/minute) |
| `DEFAULT_DURATION` | no | `60` | default run length for `generate` and `/traffic/start` (minutes) |
| `DEFAULT_TIMESCALE` | no | `1.0` | default stage-delay multiplier for `campaign run --timescale` |
| `CAMPAIGNS_DIR` | no | `./campaigns` | directory of campaign JSON definitions |
| `REPORTS_DIR` | no | `./data/campaign_reports` | directory where `campaign run` writes JSON reports (created on demand) |
| `SHIP_TIMEOUT_S` | no | `10` | per-request HTTP timeout (seconds) |
| `SHIP_MAX_RETRIES` | no | `3` | retries on 5xx/transport errors only |
| `DEMO_PORT` | no | `8020` | port for `demo-server serve` |
| `STORE_PATH` | no | `data/responses.db` | SQLite response-store path |

The API key is never logged and never written to the store; `repr()` of the
settings object redacts it. `.env` is gitignored — never commit keys.

## Usage — Traffic Generation

Continuous traffic with a category mix (SIGINT stops gracefully after the
current send):

```bash
uv run demo-server generate --rate 50 --duration 30
uv run demo-server generate --rate 60 --duration 5 --mix net=30,ato=20,benign=50 --jitter 0.2
uv run demo-server generate          # uses DEFAULT_RATE (10/min) for DEFAULT_DURATION (60 min)
```

`--rate` is events per minute; `--duration` is minutes. Omitted flags fall
back to `DEFAULT_RATE` / `DEFAULT_DURATION`. The mix splits the rate across
scenario groups (`net`, `ato`, `benign` — percentages summing to 100).

Other one-shot commands:

```bash
uv run demo-server ship-once payloads.example.json   # ship a JSON payload batch
uv run demo-server responses --limit 10              # query the store
uv run demo-server counts                            # attempts by status
uv run demo-server replay --from 2026-09-26T00:00:00 --to 2026-09-26T23:59:00
uv run demo-server serve                             # HTTP control API on :8020
```

## Usage — Campaigns

```bash
uv run demo-server campaign list
uv run demo-server campaign run --name cred_stuffing --timescale 0.5
uv run demo-server campaign run --name apt_mixed --attacker-ip 203.0.113.10
uv run demo-server campaign report --limit 10
```

- `campaign list` — every campaign with its stages (needs no API key).
- `campaign run` — executes each stage in order (delays scaled by
  `--timescale`, default `DEFAULT_TIMESCALE`), asserts gateway severity
  against each stage's expectation,
  and reports closed-loop auto-enforcement (`blocked_permanently` +
  matched indicator). A JSON run report is written to `REPORTS_DIR`.
- `campaign report` — recent gateway calls from the store with severity,
  verdict, and blocked-indicator match columns.
- `--attacker-ip` overrides the attacker IP in every stage payload;
  without it each campaign uses its `default_attacker_ip`.

## Available Campaigns

Built-in definitions live in [`campaigns/`](campaigns/) as validated JSON.

| Campaign | Stages | What it tests |
|---|---|---|
| `cred_stuffing` | 3 | Failed-login burst (brute-force trigger), Berlin→Sydney impossible travel (T1078), success-after-failures stuffing — exercises the account-takeover analyzer end to end. |
| `c2_beacon_wave` | 3 | Command-and-control beacons on ports 4444 / 8888 / 1337 with a parameterized attacker IP — exercises suspicious-port detection and indicator registration/blocking. |
| `exfil_spike` | 3 | C2 backdoor probe, 22.5 MB exfiltration spike (threshold 10 MB), API rate-abuse flood (threshold 50 req/min) — exercises the network analyzer's volume and rate rules. |
| `apt_mixed` | 5 | Full APT lifecycle across both analyzers: brute-force initial access, impossible-travel persistence, C2 implantation, mass exfiltration, API-flood cover traffic. |

Every payload uses trigger rules verified against the detectors: exfil
> 10 MB, suspicious ports {4444, 8888, 1337, 31337, 6667}, API rate abuse
> 50 req/min, failed burst ≥ 3, impossible travel < 60 min, success after
≥ 2 consecutive failures.

## Reporting

- **Per-run JSON reports** — every `campaign run` persists a timestamped
  summary (stage table, severities, verdicts, auto-block counts) under
  `REPORTS_DIR` (`./data/campaign_reports` by default):

  ```bash
  ls data/campaign_reports/
  # cred_stuffing_20261002T101500Z.json
  ```

- **Store report** — `uv run demo-server campaign report --limit 10` shows
  the most recent gateway calls with severity, verdict, and
  `BLOCKED_MATCH` columns.
- **Latency/status metrics** — `curl localhost:8020/traffic/metrics`
  returns totals, status/severity mixes and p50/p95 latencies for the last
  hour.

## Adding Custom Campaigns

1. Create `campaigns/<your_name>.json` (filename must equal the `name`).

   ```json
   {
     "name": "insider_exfil",
     "description": "Slow-drip insider exfiltration",
     "default_attacker_ip": "198.51.100.77",
     "stages": [
       {
         "name": "stage1_beacon",
         "action": "analyze_network",
         "expected_severity": "critical",
         "delay_s": 1.0,
         "description": "Low-volume beacon to dropbox host",
         "payload": {
           "flows": [
             {"source_ip": "10.0.5.5", "dest_ip": "{attacker_ip}",
              "port": 4444, "bytes_out": 4096, "protocol": "TCP", "duration_s": 60}
           ]
         }
       }
     ]
   }
   ```

2. Schema rules (validated on load — bad files fail `campaign list/run`
   with the exact reason):
   - top level: `name` (matches filename), `description`, optional
     `default_attacker_ip`, non-empty `stages` list;
   - each stage: unique `name`; `action` one of `analyze_network`,
     `analyze_ato`, `analyze_email`, `analyze_url`, `analyze_media`;
     `expected_severity` one of `low|medium|high|critical`; `delay_s` ≥ 0;
     non-empty `payload` object;
   - use the string token `"{attacker_ip}"` anywhere in the payload — it is
     substituted with `--attacker-ip` or `default_attacker_ip` at runtime.
3. Verify it loads, then run it:

   ```bash
   uv run demo-server campaign list
   uv run demo-server campaign run --name insider_exfil
   ```

Custom campaigns can also live elsewhere — point `CAMPAIGNS_DIR` at any
directory of JSON files.

## Service endpoints (port 8020)

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness + exact gateway endpoint it will ship to |
| POST | `/traffic/start` | start background generator `{rate, duration, mix, jitter}` → `{job_id}` (rate/duration default to `DEFAULT_RATE`/`DEFAULT_DURATION`) |
| GET | `/traffic/status?job_id=…` | state (running/stopped) + events_shipped + success_rate + last_event_ts |
| POST | `/traffic/stop` | graceful stop `{job_id}` (idempotent) |
| GET | `/traffic/metrics` | last-hour `{total, by_action, by_status, by_severity, latency_ms{p50,p95}, success_rate}` |
| POST | `/traffic/replay` | re-ship a stored window `{from_ts, to_ts}` |
| GET | `/responses?limit=&action=&min_status=` | query the store |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `configuration error: PROJECT_SLUG is required…` | No slug in env or `.env` — set it (step: Setup) and run from the project dir, or ensure `.env` sits in the project root. |
| `configuration error: A gateway key is required…` | Neither `MASTER_API_KEY` nor `KEY_FILE` set (or both — exactly one). |
| `campaign error: campaigns directory not found…` | Bad `CAMPAIGNS_DIR` — point it at the `campaigns/` folder. |
| `/health` OK but `success_rate` 0 with `transport_error` statuses | Backend not reachable at `GATEWAY_URL` — start it or fix the URL. |
| 401 statuses | Key revoked, wrong slot (viewer key can't ship), or key belongs to another project — reissue a master key. |
| 429 statuses | Gateway rate limit — lower `--rate`. 4xx is never retried by design. |
| Severity `MISMATCH DETECTED` in a run report | Gateway response severity differed from the stage expectation — check the analyzer rules/thresholds. |

## Architecture

```
src/demo_server/
├── config.py          # Settings (pydantic-settings): env/.env loading, fail-fast validation
├── payloads.py        # ship-once payload-file parsing
├── shipper.py         # HTTP client: retries, backoff, store writes
├── campaign_runner.py # campaign JSON loading/validation + execution + reports
├── traffic.py         # continuous generator (rate, jitter, graceful stop)
├── scenarios.py       # scenario book + mix parsing (scenarios/*.json)
├── service.py         # FastAPI control API (port 8020)
├── store.py           # SQLite (WAL) record of every attempt
├── metrics.py         # store rollups: status/severity mixes, percentiles
├── replay.py          # window replay of stored successful calls
└── cli.py             # Typer command-line interface (python -m demo_server)
```

## Tests

```bash
uv run pytest
```
