"""Monotonic blend of heuristic severity and ML probability for log lines
(LOG-ML-P2) — mirrors ml_inference.blend_scores' safety principle:

    a trained model may RAISE a weak heuristic verdict, but may NEVER lower a
    strong heuristic one (critical/high).

ml_probability semantics: probability that the line is NOT benign, i.e.
P(suspicious) + P(malicious) from the 3-class log_threat model.
"""

from __future__ import annotations

SEVERITY_BASE = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 30,
    "info": 10,
}

STRONG_SEVERITIES = ("critical", "high")


def blend_scores(heuristic_severity: str, ml_probability: float) -> dict:
    """Blend one heuristic severity with one ML probability.

    - heuristic critical/high: severity unchanged, risk_score = max(base, ml_score)
    - heuristic medium/low/info: ML may raise severity — >0.95 -> critical,
      >0.80 -> high — and risk_score = max(base, ml_score)
    Returns {"risk_score": 0-100, "severity": critical|high|medium|low}.
    (info severity only exists on the heuristic side; the blended result never
    returns below "low" once ML is consulted, matching the unified contract.)
    """
    if heuristic_severity not in SEVERITY_BASE:
        raise ValueError(f"unknown severity: {heuristic_severity!r}")
    ml_probability = max(0.0, min(1.0, float(ml_probability)))
    base = SEVERITY_BASE[heuristic_severity]
    ml_score = round(ml_probability * 100)

    if heuristic_severity in STRONG_SEVERITIES:
        return {"risk_score": max(base, ml_score), "severity": heuristic_severity}

    severity = "low" if heuristic_severity == "info" else heuristic_severity
    if ml_probability > 0.95:
        severity = "critical"
    elif ml_probability > 0.80:
        severity = "high"
    return {"risk_score": max(base, ml_score), "severity": severity}
