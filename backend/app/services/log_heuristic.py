"""Rule-based heuristic layer for log lines (LOG-ML-P2).

The ML model (log_threat_v1) NEVER lowers what this layer decides — see
log_blend.blend_scores. Severity scale: critical | high | medium | low | info.

MITRE coverage (mirrors the org analyzer's techniques + the mission list):
    T1110 Brute Force                    failed/invalid auth attempts
    T1078 Valid Accounts                 successful logins from unusual sources
    T1548 Abuse Elevation Control        sudo/su failures
    T1059 Command and Scripting Interpreter
    (operational anomalies carry no MITRE tag on purpose)
"""

from __future__ import annotations

import re

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PRIVATE_RE = re.compile(
    r"\b(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)

_ANOMALY_KEYWORDS = ("segfault", "core dump", "tlb error", "parity error", "kernel panic")


def _indicator(itype: str, value: str) -> dict:
    return {"type": itype, "value": value}


def classify_heuristic(raw_line: str) -> dict:
    """Classify one raw log line. Returns {severity, indicators, mitre}.

    First match wins (rules are ordered most-specific first); a line that
    matches nothing is severity=info with no indicators.
    """
    low = raw_line.lower()
    indicators: list[dict] = []
    mitre: list[str] = []

    ip = _IPV4_RE.search(raw_line)
    ip_value = ip.group(0) if ip else ""

    # T1110 — Brute Force: failed password attempts on ssh
    if "failed password" in low or "invalid user" in low:
        if ip_value:
            indicators.append(_indicator("source_ip", ip_value))
        user = re.search(r"for (?:invalid user )?(\S+)", raw_line, re.IGNORECASE)
        if user:
            indicators.append(_indicator("username", user.group(1)))
        indicators.append(_indicator("auth_failure", raw_line.strip()[:120]))
        return {"severity": "high", "indicators": indicators, "mitre": ["T1110"]}

    if "authentication failure" in low:
        if ip_value:
            indicators.append(_indicator("source_ip", ip_value))
        indicators.append(_indicator("auth_failure", raw_line.strip()[:120]))
        return {"severity": "high", "indicators": indicators, "mitre": ["T1110"]}

    if "break-in attempt" in low:
        indicators.append(_indicator("dns_probe", raw_line.strip()[:120]))
        return {"severity": "medium", "indicators": indicators, "mitre": ["T1110"]}

    # T1548 — Abuse Elevation Control Mechanism: sudo/su failures
    if "sudo" in low and "incorrect password" in low:
        indicators.append(_indicator("elevation_failure", raw_line.strip()[:120]))
        return {"severity": "high", "indicators": indicators, "mitre": ["T1548"]}

    if "failed su" in low or ("su:" in low and "fail" in low):
        indicators.append(_indicator("elevation_failure", raw_line.strip()[:120]))
        return {"severity": "high", "indicators": indicators, "mitre": ["T1548"]}

    # T1059 — Command execution surfaced through sudo
    if "command=" in low:
        cmd = re.search(r"COMMAND=(.+)$", raw_line, re.IGNORECASE)
        indicators.append(_indicator("command", (cmd.group(1) if cmd else "").strip()[:120]))
        return {"severity": "medium", "indicators": indicators, "mitre": ["T1059"]}

    # T1078 — Valid Accounts: successful login from an unusual (external) source
    if re.search(r"accepted (?:password|publickey)", low):
        if ip_value and not _PRIVATE_RE.match(ip_value):
            indicators.append(_indicator("source_ip", ip_value))
            indicators.append(_indicator("unusual_source", "external ip on successful login"))
            return {"severity": "medium", "indicators": indicators, "mitre": ["T1078"]}
        return {"severity": "info", "indicators": indicators, "mitre": []}

    # Operational anomalies — anomalous but not attacker activity
    for kw in _ANOMALY_KEYWORDS:
        if kw in low:
            indicators.append(_indicator("operational_anomaly", kw))
            return {"severity": "low", "indicators": indicators, "mitre": []}

    return {"severity": "info", "indicators": indicators, "mitre": mitre}
