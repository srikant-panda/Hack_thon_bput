"""Prompt templates for the Explainable AI engine (Part 3)."""

import json
from typing import Any

PHISHING_SYSTEM_PROMPT = (
    "You are CYBERGUARD, an AI cybersecurity analyst. Analyze the provided "
    "email, heuristic indicators, and the system's assessed severity level. "
    "Return a strict JSON object with keys: "
    "'explanation' (string, detailed human-readable paragraph starting with "
    "the assessed risk level, e.g. 'Safe: ...' or 'High Risk: ...'), "
    "'mitre_techniques' (array of objects with 'id' and 'name'; MUST be empty [] if severity is SAFE), "
    "'recommended_actions' (array of strings)."
)

URL_SYSTEM_PROMPT = (
    "You are CYBERGUARD, an AI cybersecurity analyst. Analyze the provided "
    "URL, its lexical characteristics, heuristic indicators, and the system's assessed severity level. "
    "Return a strict JSON object with keys: "
    "'explanation' (string, detailed human-readable paragraph starting with "
    "the assessed risk level, e.g. 'Safe: ...' or 'High Risk: ...'), "
    "'mitre_techniques' (array of objects with 'id' and 'name'; MUST be empty [] if severity is SAFE), "
    "'recommended_actions' (array of strings)."
)

IMPERSONATION_SYSTEM_PROMPT = (
    "You are CYBERGUARD, an AI cybersecurity analyst. Analyze the provided "
    "message, heuristic indicators, and the system's assessed severity level. "
    "Return a strict JSON object with keys: "
    "'explanation' (string, detailed human-readable paragraph starting with "
    "the assessed risk level, e.g. 'Safe: ...' or 'High Risk: ...'), "
    "'mitre_techniques' (array of objects with 'id' and 'name'; MUST be empty [] if severity is SAFE), "
    "'recommended_actions' (array of strings)."
)

ACCOUNT_TAKEOVER_SYSTEM_PROMPT = (
    "You are CYBERGUARD, an AI cybersecurity analyst. Analyze the provided "
    "authentication events, heuristic indicators, and the system's assessed severity level. "
    "Return a strict JSON object with keys: "
    "'explanation' (string, detailed human-readable paragraph starting with "
    "the assessed risk level, e.g. 'Safe: ...' or 'High Risk: ...'), "
    "'mitre_techniques' (array of objects with 'id' and 'name'; MUST be empty [] if severity is SAFE), "
    "'recommended_actions' (array of strings)."
)

NETWORK_THREAT_SYSTEM_PROMPT = (
    "You are CYBERGUARD, an AI cybersecurity analyst. Analyze the provided "
    "network flows, API logs, heuristic indicators, and the system's assessed severity level. "
    "Return a strict JSON object with keys: "
    "'explanation' (string, detailed human-readable paragraph starting with "
    "the assessed risk level, e.g. 'Safe: ...' or 'High Risk: ...'), "
    "'mitre_techniques' (array of objects with 'id' and 'name'; MUST be empty [] if severity is SAFE), "
    "'recommended_actions' (array of strings)."
)

DEEPFAKE_SYSTEM_PROMPT = (
    "You are CYBERGUARD, an AI cybersecurity analyst specialising in media "
    "forensics. Given forensic indicators, the analysis method, and the assessed severity level, "
    "return strict JSON with keys: "
    "'explanation' (human-readable paragraph starting with the assessed risk level stating authenticity and evidence), "
    "'mitre_techniques' (array of objects with id and name; MUST be empty [] if assessed as safe), "
    "'recommended_actions' (array of strings; must include 'Flag multimedia for manual verification' "
    "whenever manipulation_probability is above 0.5)."
)

SOC_ASSISTANT_SYSTEM_PROMPT = (
    "You are the CYBERGUARD SOC Assistant, an AI-powered cybersecurity "
    "operations assistant. You help security analysts by answering "
    "questions about current threats, explaining alerts, suggesting "
    "investigation steps, and providing MITRE ATT&CK context. Use the "
    "provided alert context to give specific, actionable answers. Always "
    "be precise and cite alert IDs when relevant."
)


def _format_alignment_instructions(risk_score: int, severity: str) -> str:
    sev_upper = severity.upper()
    if severity == "safe":
        return (
            f"EVALUATED VERDICT:\n"
            f"- RISK SCORE: {risk_score}/100\n"
            f"- SEVERITY: SAFE (BENIGN)\n\n"
            f"CRITICAL REQUIREMENT:\n"
            f"The detection engine has classified this event as SAFE. Your explanation MUST confirm "
            f"why this item is benign and safe (e.g. legitimate communication, no phishing links, "
            f"no suspicious urgency, no credential harvesting). Do NOT contradict this or label it as "
            f"medium or high risk. 'mitre_techniques' MUST be an empty array []. "
            f"'recommended_actions' should be ['No action required']."
        )
    return (
        f"EVALUATED VERDICT:\n"
        f"- RISK SCORE: {risk_score}/100\n"
        f"- SEVERITY: {sev_upper}\n\n"
        f"CRITICAL REQUIREMENT:\n"
        f"Your explanation MUST strictly align with the assessed severity level '{sev_upper}'. "
        f"Start your explanation paragraph with '{severity.capitalize()} Risk: ' and explain the "
        f"specific indicators that contributed to this threat score, citing corresponding MITRE ATT&CK techniques."
    )


def format_phishing_user_prompt(
    payload: dict[str, Any],
    indicators: list[dict],
    risk_score: int = 0,
    severity: str = "safe",
) -> str:
    """Build the user prompt for phishing email analysis."""
    alignment = _format_alignment_instructions(risk_score, severity)
    return (
        f"{alignment}\n\n"
        f"Email data:\n{json.dumps(payload, indent=2, default=str)}\n\n"
        f"Heuristic indicators detected:\n{json.dumps(indicators, indent=2)}\n\n"
        "Respond with the strict JSON object described in the system prompt."
    )


def format_url_user_prompt(
    url: str,
    indicators: list[dict],
    risk_score: int = 0,
    severity: str = "safe",
) -> str:
    """Build the user prompt for URL analysis."""
    alignment = _format_alignment_instructions(risk_score, severity)
    return (
        f"{alignment}\n\n"
        f"URL: {json.dumps(url)}\n\n"
        f"Heuristic indicators detected:\n{json.dumps(indicators, indent=2)}\n\n"
        "Respond with the strict JSON object described in the system prompt."
    )


def format_impersonation_user_prompt(
    payload: dict[str, Any],
    indicators: list[dict],
    risk_score: int = 0,
    severity: str = "safe",
) -> str:
    """Build the user prompt for digital impersonation analysis."""
    alignment = _format_alignment_instructions(risk_score, severity)
    return (
        f"{alignment}\n\n"
        f"Message data:\n{json.dumps(payload, indent=2, default=str)}\n\n"
        f"Heuristic indicators detected:\n{json.dumps(indicators, indent=2)}\n\n"
        "Respond with the strict JSON object described in the system prompt."
    )


def format_account_takeover_user_prompt(
    auth_events: list[dict],
    indicators: list[dict],
    risk_score: int = 0,
    severity: str = "safe",
) -> str:
    """Build the user prompt for account takeover analysis."""
    alignment = _format_alignment_instructions(risk_score, severity)
    return (
        f"{alignment}\n\n"
        f"Authentication events:\n{json.dumps(auth_events, indent=2, default=str)}\n\n"
        f"Heuristic indicators detected:\n{json.dumps(indicators, indent=2)}\n\n"
        "Respond with the strict JSON object described in the system prompt."
    )


def format_network_user_prompt(
    flows: list[dict],
    api_logs: list[dict],
    indicators: list[dict],
    risk_score: int = 0,
    severity: str = "safe",
) -> str:
    """Build the user prompt for network and API abuse analysis."""
    alignment = _format_alignment_instructions(risk_score, severity)
    return (
        f"{alignment}\n\n"
        f"Network flows:\n{json.dumps(flows, indent=2, default=str)}\n\n"
        f"API logs:\n{json.dumps(api_logs, indent=2, default=str)}\n\n"
        f"Heuristic indicators detected:\n{json.dumps(indicators, indent=2)}\n\n"
        "Respond with the strict JSON object described in the system prompt."
    )


def format_deepfake_user_prompt(
    result: dict[str, Any],
    risk_score: int = 0,
    severity: str = "safe",
) -> str:
    """Build the user prompt for media forensics analysis."""
    alignment = _format_alignment_instructions(risk_score, severity)
    summary = {
        "analysis_method": result.get("method"),
        "simulated": result.get("simulated"),
        "media_type": result.get("media_type"),
        "authenticity_score": result.get("authenticity_score"),
        "manipulation_probability": result.get("manipulation_probability"),
        "indicators": result.get("indicators", []),
    }
    return (
        f"{alignment}\n\n"
        f"Forensic result:\n{json.dumps(summary, indent=2, default=str)}\n\n"
        "Respond with the strict JSON object described in the system prompt."
    )
