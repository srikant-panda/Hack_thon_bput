"""OpenRouter client with distributed API key rotation, fallback models, and defensive parsing."""

import json
import logging
from typing import Any, Optional

import httpx

from app.ai.key_rotator import get_key_rotator
from app.core.config import get_settings

logger = logging.getLogger("cyberguard.openrouter")

OPENROUTER_CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"
REQUEST_TIMEOUT_SECONDS = 10
HTTP_REFERER = "https://cyberguard.local"
APP_TITLE = "CYBERGUARD"


def _normalize_severity(score: int) -> str:
    if score <= 20:
        return "safe"
    if score <= 40:
        return "low"
    if score <= 60:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


def _parse_llm_content(content: str) -> Optional[dict[str, Any]]:
    """Parse JSON defensively from LLM output by extracting outermost braces."""
    if not content:
        return None

    content = content.strip()
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Find outermost braces
    start = content.find("{")
    end = content.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = content[start : end + 1]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    return None


def generate_heuristic_explanation(
    module: str,
    indicators: list[dict[str, Any]],
    raw_data: Optional[dict[str, Any]] = None,
    risk_score: int = 0,
) -> dict[str, Any]:
    """Generate high-quality heuristic explanation and MITRE mappings aligned with severity."""
    raw_data = raw_data or {}
    severity = _normalize_severity(risk_score)

    if severity == "safe":
        return {
            "explanation": (
                f"Safe (Risk Score {risk_score}/100): Heuristic analysis and trained models evaluated "
                "this artifact as benign. No malicious links, credential harvesting attempts, "
                "or deceptive anomalies were identified."
            ),
            "mitre_techniques": [],
            "recommended_actions": ["No action required", "Permit standard handling"],
        }

    descriptions = [ind.get("description") for ind in indicators if isinstance(ind, dict) and ind.get("description")]
    summary_reasons = "; ".join(descriptions[:3]) if descriptions else "Multiple forensic indicators matched."

    # Module-specific defaults
    if module == "phishing":
        mitre = [
            {"id": "T1566.001", "name": "Spearphishing Attachment/Link"},
            {"id": "T1566.002", "name": "Spearphishing Link"},
        ]
        actions = ["Quarantine email", "Warn the user", "Block suspicious URL"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Phishing indicators detected: {summary_reasons}. "
            "The message attempts to deceive the recipient into interacting with malicious links or disclosing credentials."
        )

    elif module == "url":
        mitre = [
            {"id": "T1566.002", "name": "Spearphishing Link"},
            {"id": "T1204.001", "name": "Malicious Link"},
        ]
        actions = ["Block suspicious URL", "Warn the user"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Suspicious URL characteristics identified: {summary_reasons}. "
            "The URL displays markers common in malware delivery, credential harvesting, or deceptive redirects."
        )

    elif module == "impersonation":
        mitre = [
            {"id": "T1656", "name": "Impersonation"},
            {"id": "T1566", "name": "Phishing"},
        ]
        actions = ["Report impersonation", "Warn the user", "Notify administrator/SOC"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Digital impersonation pattern detected: {summary_reasons}. "
            "The communication mimics authority figures with urgency, unusual financial requests, or secrecy demands."
        )

    elif module == "account_takeover":
        mitre = [
            {"id": "T1110.003", "name": "Password Spraying"},
            {"id": "T1078", "name": "Valid Accounts"},
        ]
        actions = ["Revoke active session", "Require additional authentication", "Notify administrator/SOC"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Account takeover anomaly detected: {summary_reasons}. "
            "Anomalous authentication behavior indicates potential credential stuffing, brute-forcing, or impossible travel."
        )

    elif module in ("network", "api_abuse"):
        mitre = [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1499", "name": "Endpoint Denial of Service"},
        ]
        actions = ["Block suspicious IP/device", "Notify administrator/SOC"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Network/API threat pattern detected: {summary_reasons}. "
            "Traffic exhibits characteristics of abnormal data exfiltration, command-and-control ports, or rate abuse."
        )

    elif module == "deepfake":
        mitre = [
            {"id": "T1656", "name": "Impersonation via Synthetic Media"},
        ]
        actions = ["Flag multimedia for manual verification", "Notify administrator/SOC"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Media manipulation / synthetic artifact detected: {summary_reasons}. "
            "Forensics analysis indicates anomalous error-level variance, spectral distortion, or AI synthesis signatures."
        )

    else:
        mitre = [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
        actions = ["Notify administrator/SOC", "Escalate the incident for investigation"]
        explanation = f"{severity.capitalize()} Risk (Score {risk_score}/100): Threat activity detected: {summary_reasons}."

    return {
        "explanation": explanation,
        "mitre_techniques": mitre,
        "recommended_actions": actions,
    }


def _enforce_severity_consistency(output: dict[str, Any], risk_score: int) -> dict[str, Any]:
    """Ensure LLM generated explanation and MITRE techniques strictly match assessed severity."""
    severity = _normalize_severity(risk_score)
    if severity == "safe":
        output["mitre_techniques"] = []
        raw_exp = str(output.get("explanation", "")).strip()
        lowered = raw_exp.lower()
        contradictory = any(
            phrase in lowered
            for phrase in [
                "high risk",
                "critical risk",
                "medium-high risk",
                "medium risk",
                "fake order notification",
                "exhibits multiple phishing indicators",
                "potential lure for credential harvesting",
            ]
        )
        if contradictory or not lowered.startswith("safe"):
            output["explanation"] = (
                f"Safe (Risk Score {risk_score}/100): Automated heuristics and trained ML models verified "
                "this content as benign with a low risk probability. No deceptive links, credential harvesting, "
                "or social engineering indicators were detected."
            )
        output["recommended_actions"] = ["No action required", "Permit standard handling"]
    return output


async def call_openrouter(
    system_prompt: str,
    user_prompt: str,
    module: str = "general",
    indicators: Optional[list[dict[str, Any]]] = None,
    raw_data: Optional[dict[str, Any]] = None,
    risk_score: int = 0,
) -> dict[str, Any]:
    """Call OpenRouter chat completions with distributed key rotation, circuit breaking, and fallbacks."""
    settings = get_settings()
    indicators = indicators or []
    rotator = get_key_rotator()

    # Build fallback explanation ready if needed
    heuristic_fallback = generate_heuristic_explanation(
        module=module,
        indicators=indicators,
        raw_data=raw_data,
        risk_score=risk_score,
    )

    configured_keys = settings.openrouter_keys_list
    if not configured_keys:
        logger.info("No OPENROUTER_API_KEY configured; using synthesized heuristic explanation")
        return _enforce_severity_consistency(heuristic_fallback, risk_score)

    # Model candidates to attempt sequentially
    models_to_try = [settings.OPENROUTER_MODEL]
    for fallback in settings.fallback_models_list:
        if fallback not in models_to_try:
            models_to_try.append(fallback)

    max_key_attempts = max(2, len(configured_keys))

    async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS)) as client:
        for model in models_to_try:
            for _ in range(max_key_attempts):
                api_key, masked_key = await rotator.get_next_key()
                if not api_key:
                    break

                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": HTTP_REFERER,
                    "X-Title": APP_TITLE,
                }

                payload = {
                    "model": model,
                    "messages": [
                        {
                            "role": "system",
                            "content": f"{system_prompt}\nIMPORTANT: You must respond ONLY with a valid JSON object matching the requested schema. Do NOT include markdown code fences or conversational text.",
                        },
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.1,
                }

                try:
                    response = await client.post(OPENROUTER_CHAT_URL, headers=headers, json=payload)
                    if response.status_code == 200:
                        rotator.mark_key_success(api_key)
                        body = response.json()
                        content = body["choices"][0]["message"]["content"]
                        parsed = _parse_llm_content(content)
                        if parsed and "explanation" in parsed:
                            parsed.setdefault("mitre_techniques", heuristic_fallback["mitre_techniques"])
                            parsed.setdefault("recommended_actions", heuristic_fallback["recommended_actions"])
                            return _enforce_severity_consistency(parsed, risk_score)
                        logger.warning("Model %s output could not be parsed as JSON, trying next candidate...", model)
                        break  # Advance to next candidate model
                    elif response.status_code == 429:
                        rotator.mark_key_down(api_key, reason="Rate limited (429)", status_code=429)
                        logger.warning("Key %s rate limited on model %s, rotating to next key...", masked_key, model)
                        continue  # Try next key with distributed load
                    elif response.status_code in (401, 402):
                        rotator.mark_key_down(api_key, reason="Auth/Quota error", status_code=response.status_code)
                        logger.warning("Key %s returned HTTP %s on model %s, rotating to next key...", masked_key, response.status_code, model)
                        continue  # Try next key
                    elif response.status_code in (404, 503):
                        logger.warning("Model %s returned HTTP %s, trying next candidate model...", model, response.status_code)
                        break  # Advance to next model
                    else:
                        logger.warning("OpenRouter error on model %s with key %s: HTTP %s %s", model, masked_key, response.status_code, response.text[:200])
                        break
                except Exception as exc:
                    rotator.mark_key_down(api_key, reason=f"Network error: {exc}")
                    logger.warning("OpenRouter request failed for model %s with key %s: %s", model, masked_key, exc)
                    continue

    # If all models/keys failed, use the synthesized explanation
    logger.info("Using synthesized heuristic explanation for %s alert", module)
    return _enforce_severity_consistency(heuristic_fallback, risk_score)
