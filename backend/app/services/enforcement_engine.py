"""Evaluates alerts against EnforcementPolicy and produces EnforcementDecisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.core.mode_detector import OperationMode
from app.db.models import Alert, EnforcementPolicy


# Map Alert.module -> (high_threshold_attr, medium_threshold_attr) on EnforcementPolicy
_MODULE_THRESHOLD_ATTRS: dict[str, tuple[str, str]] = {
    "phishing":         ("phishing_high_threshold",     "phishing_medium_threshold"),
    "url":              ("phishing_high_threshold",     "phishing_medium_threshold"),  # reuse phishing thresholds for URLs
    "impersonation":    ("impersonation_high_threshold", "impersonation_medium_threshold"),
    "account_takeover": ("ato_high_threshold",          "ato_medium_threshold"),
    "network":          ("network_high_threshold",      "network_medium_threshold"),
    "api_abuse":        ("network_high_threshold",      "network_medium_threshold"),
    "deepfake":         ("deepfake_high_threshold",     "deepfake_medium_threshold"),
    "media":            ("deepfake_high_threshold",     "deepfake_medium_threshold"),
}

# Map enforcement severity -> policy action attribute
_SEVERITY_ACTION_ATTR = {
    "critical": "action_on_critical",
    "high":     "action_on_high",
    "medium":   "action_on_medium",
    "low":      "action_on_low",
}

_SEVERITY_AUTO_ATTR = {
    "critical": "auto_execute_critical",
    "high":     "auto_execute_high",
    "medium":   "auto_execute_medium",
    "low":      "auto_execute_low",
}


@dataclass
class EnforcementDecision:
    """Output of the policy engine for a single alert."""
    alert_id: Optional[str]
    enforcement_severity: str          # critical | high | medium | low
    action_type: str                   # e.g. "quarantine_email"
    auto_execute: bool                 # True => run immediately; False => pending_approval
    requires_approval: bool            # inverse of auto_execute in server mode
    notify_soc: bool
    notify_user: bool
    policy_id: Optional[str]
    mode: OperationMode
    reason: str                        # human-readable explanation for audit log


def _classify_enforcement_severity(alert: Alert, policy: EnforcementPolicy) -> str:
    """Map risk_score -> enforcement severity using per-module thresholds."""
    attrs = _MODULE_THRESHOLD_ATTRS.get(alert.module)
    if attrs is None:
        # Unknown module — fall back to display severity so we never crash.
        # Display severity may be "safe", which has no enforcement band; clamp to "low".
        fallback = (alert.severity or "low").lower()
        return fallback if fallback in _SEVERITY_ACTION_ATTR else "low"

    high_attr, medium_attr = attrs
    high_threshold = getattr(policy, high_attr)
    medium_threshold = getattr(policy, medium_attr)

    score = alert.risk_score or 0
    if score >= 90:
        return "critical"
    if score >= high_threshold:
        return "high"
    if score >= medium_threshold:
        return "medium"
    return "low"


class EnforcementEngine:
    """Pure, synchronous policy evaluator. No DB writes — that's the caller's job."""

    def evaluate(
        self,
        alert: Alert,
        policy: EnforcementPolicy,
        mode: OperationMode,
        request_auto_execute: bool = False,
    ) -> EnforcementDecision:
        severity = _classify_enforcement_severity(alert, policy)

        action_attr = _SEVERITY_ACTION_ATTR[severity]
        auto_attr = _SEVERITY_AUTO_ATTR[severity]
        action_type = getattr(policy, action_attr)
        policy_auto = getattr(policy, auto_attr)

        # In client mode we NEVER auto-execute, regardless of policy.
        if mode == OperationMode.CLIENT:
            auto_execute = False
            requires_approval = False  # there is no approval in client mode; it's just a recommendation
            reason = (
                f"Client mode: action '{action_type}' recorded as recommendation only. "
                f"Enforcement severity={severity}, risk_score={alert.risk_score}."
            )
        else:
            # Server mode: honour policy, but allow caller to downgrade to manual via auto_execute=False
            auto_execute = policy_auto and request_auto_execute
            requires_approval = not auto_execute and action_type not in ("allow",)
            reason = (
                f"Server mode: severity={severity}, policy_action={action_type}, "
                f"policy_auto={policy_auto}, request_auto_execute={request_auto_execute}."
            )

        notify_soc = (
            (severity == "critical" and policy.notify_soc_on_critical)
            or (severity == "high" and policy.notify_soc_on_high)
        )
        notify_user = (severity == "medium" and policy.notify_user_on_medium)

        return EnforcementDecision(
            alert_id=alert.id,
            enforcement_severity=severity,
            action_type=action_type,
            auto_execute=auto_execute,
            requires_approval=requires_approval,
            notify_soc=notify_soc,
            notify_user=notify_user,
            policy_id=policy.id,
            mode=mode,
            reason=reason,
        )


# Module-level singleton — cheap to construct, stateless.
enforcement_engine = EnforcementEngine()
