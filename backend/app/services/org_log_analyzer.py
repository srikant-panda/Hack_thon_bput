"""Auto-detection and analysis of ingested org logs (ORG-2).

The gateway (``POST /org/{org_id}/logs/ingest``) auto-detects the log type
from the payload SHAPE — never from a client-declared field — and runs the
matching detector:

- ``auth``    — sign-in/auth events (``user`` + ``ip``/``status``) → the
  Phase-1 account-takeover detector (impossible travel, brute force, …).
- ``network`` — flows / API logs (``src_ip``/``dst_ip``/``port``/``bytes``
  or ``flows``/``api_logs``) → the network & API-abuse analyzer.
- ``app``     — everything else (timestamp/level/message app logs) → a
  keyword/pattern detector (auth failures, privilege escalation, injection
  probes, exfiltration markers).

Analysis is synchronous and deterministic (heuristics + ML blend); no LLM
call sits on the ingest path — the Splunk plane must never block on a
provider. A structured result (score, severity, indicators, summary) is
returned and stored in ``org_log_events.analysis_result``; medium+ findings
also produce an org-scoped Event + Alert so dashboards and realtime see them.
"""

import logging
import re
from typing import Any

from app.services.account_takeover_detector import analyze_auth_log_heuristics
from app.services.network_threat_detector import analyze_network_heuristics
from app.services.scoring_service import get_severity

logger = logging.getLogger("cyberguard.org_logs")

# (pattern, severity-weight, indicator-type, description)
_APP_PATTERNS: list[tuple[str, int, str, str]] = [
    (r"failed password|authentication failure|auth.*fail", 40, "auth_failure", "Authentication failure recorded in application log"),
    (r"invalid user|unknown user", 35, "invalid_user", "Login attempt for a non-existent user"),
    (r"sudo(?!l|:.*session opened).*(command|COMMAND)|privilege|escalat", 45, "privilege_escalation", "Privilege change/escalation activity"),
    (r"union select|drop table|;--|<script", 55, "injection_probe", "SQL/XSS injection probe pattern"),
    (r"\.\./\.\./|etc/passwd", 50, "path_traversal", "Path traversal attempt"),
    (r"ransom|encrypt.*files|bitcoin|xmrig|miner", 60, "malware_marker", "Known malware/ransomware marker"),
    (r"out of memory|oom|disk.*(full|95%|100%)", 25, "resource_exhaustion", "Resource exhaustion event"),
    (r"error|exception|traceback|fatal", 15, "app_error", "Application error"),
]

APP_LOG_LEVEL_WEIGHTS = {"emerg": 50, "alert": 45, "crit": 40, "error": 20, "warning": 10, "notice": 5, "info": 0, "debug": 0}


def detect_log_type(data: Any) -> str:
    """Classify a log payload by its SHAPE: auth | network | app."""
    items = data if isinstance(data, list) else [data]
    if not items or not isinstance(items[0], dict):
        return "app"

    keys = set()
    for item in items[:10]:  # sample up to 10 entries
        if isinstance(item, dict):
            keys |= {k.lower() for k in item.keys()}
        nested = item.get("events") if isinstance(item, dict) else None
        if isinstance(nested, list) and nested and isinstance(nested[0], dict):
            keys |= {k.lower() for k in nested[0].keys()}

    if {"user", "ip"} & keys and ({"status"} & keys or {"success", "failed"} & {str(v).lower() for i in items[:10] if isinstance(i, dict) for v in [i.get("status", "")]}):
        return "auth"
    if keys & {"src_ip", "dst_ip", "dest_ip", "flows", "api_logs", "bytes_in", "bytes_out"} and keys & {"port", "src_ip", "dst_ip", "flows", "api_logs"}:
        return "network"
    if keys & {"user", "ip"} and keys & {"location", "device", "action"}:
        return "auth"
    return "app"


def _normalize_auth_events(data: Any) -> list[dict[str, Any]]:
    events = data.get("events") if isinstance(data, dict) else data
    if not isinstance(events, list):
        events = [events]
    return [e for e in events if isinstance(e, dict)]


def _analyze_auth(data: dict[str, Any]) -> dict[str, Any]:
    events = _normalize_auth_events(data)
    indicators = analyze_auth_log_heuristics(events) if events else []
    score = _score_from_indicators(indicators, base=15)
    return _result("auth", score, indicators, events,
                   summary=f"Auth-log analysis of {len(events)} event(s)")


def _analyze_network(data: dict[str, Any]) -> dict[str, Any]:
    flows = data.get("flows") if isinstance(data, dict) and isinstance(data.get("flows"), list) else (
        [data] if isinstance(data, dict) and ("src_ip" in data or "dst_ip" in data or "dest_ip" in data) else []
    )
    api_logs = data.get("api_logs") if isinstance(data, dict) and isinstance(data.get("api_logs"), list) else []
    if not flows and not api_logs and isinstance(data, dict):
        flows = [data]
    indicators = analyze_network_heuristics(flows=flows, api_logs=api_logs)
    score = _score_from_indicators(indicators, base=15)
    return _result("network", score, indicators,
                   {"flows": flows, "api_logs": api_logs},
                   summary=f"Network analysis of {len(flows)} flow(s), {len(api_logs)} API log(s)")


def _analyze_app(data: Any) -> dict[str, Any]:
    entries = data if isinstance(data, list) else [data]
    indicators: list[dict[str, Any]] = []
    score = 0
    inspected = 0
    for entry in entries[:100]:
        if not isinstance(entry, dict):
            continue
        inspected += 1
        message = str(entry.get("message") or entry.get("msg") or entry)
        level = str(entry.get("level", "")).lower()
        score += APP_LOG_LEVEL_WEIGHTS.get(level, 0)
        for pattern, weight, itype, description in _APP_PATTERNS:
            if re.search(pattern, message, flags=re.IGNORECASE):
                score += weight
                indicators.append({
                    "type": itype,
                    "value": message[:160],
                    "severity": "high" if weight >= 45 else ("medium" if weight >= 25 else "low"),
                    "description": description,
                })
    if inspected == 0:
        score = max(score, 5)
    score = min(score, 100)
    return _result("app", score, indicators, entries[:20] if len(entries) > 20 else entries,
                   summary=f"Application-log scan of {inspected} entr(y/ies)")


def _score_from_indicators(indicators: list[dict[str, Any]], *, base: int) -> int:
    if not indicators:
        return base
    worst = max(str(i.get("severity", "low")) for i in indicators)
    weights = {"critical": 90, "high": 75, "medium": 50, "low": 25}
    return min(100, max(base, weights.get(worst, 25)))


def _result(log_type: str, score: int, indicators: list[dict[str, Any]],
            raw_preview: Any, summary: str) -> dict[str, Any]:
    severity = get_severity(score)
    return {
        "log_type": log_type,
        "risk_score": score,
        "severity": severity,
        "indicators": indicators,
        "summary": summary,
        "mitre_techniques": _mitre_for(log_type, indicators),
    }


def _mitre_for(log_type: str, indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if log_type == "auth":
        return [{"id": "T1110", "name": "Brute Force"}] if indicators else []
    if log_type == "network":
        return [{"id": "T1071", "name": "Application Layer Protocol"}] if indicators else []
    types = {i.get("type") for i in indicators}
    techniques = []
    if "injection_probe" in types or "path_traversal" in types:
        techniques.append({"id": "T1190", "name": "Exploit Public-Facing Application"})
    if "privilege_escalation" in types:
        techniques.append({"id": "T1548", "name": "Abuse Elevation Control Mechanism"})
    if "malware_marker" in types:
        techniques.append({"id": "T1036", "name": "Masquerading"})
    return techniques


def analyze_log(data: Any, log_type: str | None = None) -> dict[str, Any]:
    """Auto-detect (unless forced) and analyze a log payload."""
    detected = log_type or detect_log_type(data)
    analyzer = {"auth": _analyze_auth, "network": _analyze_network, "app": _analyze_app}.get(
        detected, _analyze_app
    )
    result = analyzer(data)
    result["log_type"] = detected
    return result
