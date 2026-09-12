"""SOC Assistant — strict whitelist chat service (non-disclosure policy).

The assistant answers ONLY live operational security data for the caller's
organization. All system internals (key management, models, scoring formulas,
architecture, configuration, secrets) are CLASSIFIED: probes receive a
standardized refusal and are audit-logged — probing the assistant is itself an
observable security event.

Every reply is composed deterministically from the database. No LLM is invoked
on any path: free-text generation was the leak surface this policy closes, and
deterministic composition guarantees counts and titles can never be invented.
"""

import logging
import re
from collections import Counter
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert
from app.services import audit_service

logger = logging.getLogger("cyberguard.assistant")

CONTEXT_ALERT_COUNT = 20

HELP_MENU = (
    "Here's what I can do:\n"
    "• Summarize today's threats — org-wide threat picture\n"
    "• Show critical alerts — the highest-severity items right now\n"
    "• List MITRE techniques detected — ATT&CK techniques in your alerts\n"
    "• What should I investigate first? — suggested triage order\n\n"
    "I answer from your organization's live security data only."
)

GREETING_REPLY = (
    "Hello Analyst 👋 I'm your SOC Assistant. I can summarize today's threats, "
    "show critical alerts, list MITRE techniques, or tell you what to "
    "investigate first. What do you need?"
)

REFUSAL_INTERNAL = (
    "I can't disclose CYBERGUARD system internals, including key management, "
    "models, or architecture. I can help with today's threats, critical "
    "alerts, MITRE techniques, or investigation priority. Which do you need?"
)

REFUSAL_OUT_OF_SCOPE = (
    "I only advise on CYBERGUARD's live security operations: today's threats, "
    "critical alerts, MITRE techniques, and investigation priority. Which do "
    "you need?"
)

# Ordered gate: first match wins. INTERNAL_PROBE outranks the OPS classes so a
# question like "how many keys rotate today" is treated as a probe, not stats.
_INTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("GREETING", re.compile(r"^\s*(hi|helo+|hello|hey|yo|greetings|good\s*(morning|afternoon|evening))\b", re.I)),
    ("HELP", re.compile(r"\b(help|what can you do|commands|capabilities|options)\b", re.I)),
    # --- CLASSIFIED internals (checked before anything operational) ---
    ("INTERNAL_PROBE", re.compile(
        r"rotat"                                   # rotate / rotation / rotates
        r"|api[ -]?keys?"
        r"|key management"
        r"|\bmodels?\b"
        r"|\bllms?\b"
        r"|providers?"
        r"|groq|gemini|openrouter"
        r"|algorithm|formulas?|blend|weights?|thresholds?"
        r"|architect"
        r"|internal"
        r"|how (do|does) (you|this system|the system) work"
        r"|what (do|does) (you|this system|the system) use"
        r"|source code|\bcodebase\b"
        r"|\bconfig"
        r"|\benv\b|environment variables?"
        r"|secrets?"
        r"|\bprompts?\b"
        r"|\btrain(ed|ing|s)?\b|datasets?"
        r"|\bendpoints?\b"
        r"|\bschemas?\b"
        r"|ignore (all |any )?(previous|prior) instructions"
        r"|you are now\b"
        r"|repeat (your|the) (system )?prompt"
        r"|print (your|the) (system )?(prompt|config)"
        r"|(judge|admin) (requires?|demands?|says?)"
        r"|requires? disclosure"
        r"|base64"
        r"|hex[- ]?decod",
        re.I,
    )),
    ("OPS_STATS", re.compile(r"\b(stats?|summaries?|summary|overview|sitrep|situation report|threat picture|todays?|count|how many|current threats|today'?s? threats)\b", re.I)),
    ("OPS_CRITICAL", re.compile(r"\b(critical|worst|severe)\b", re.I)),
    ("OPS_MITRE", re.compile(r"\b(mitre|att&ck|techniques?)\b", re.I)),
    ("OPS_PRIORITIZE", re.compile(r"\b(investigate|priorit\w*|triage|what next|first)\b", re.I)),
]


def classify_intent(message: str) -> str:
    """Whitelist intent gate. Anything unmatched is out of scope."""
    for intent, pattern in _INTENT_PATTERNS:
        if pattern.search(message):
            return intent
    return "OUT_OF_SCOPE"


async def _load_alerts(db: AsyncSession, organization_id: str, limit: int = 500) -> list[Alert]:
    result = await db.execute(
        select(Alert)
        .where(Alert.organization_id == organization_id)
        .order_by(desc(Alert.created_at))
        .limit(limit)
    )
    return list(result.scalars().all())


async def _reply_summary(db: AsyncSession, organization_id: str) -> tuple[str, list[str]]:
    alerts = await _load_alerts(db, organization_id)
    ids = [a.id for a in alerts]
    if not alerts:
        return "No alerts have been recorded for your organization yet. Once detections fire, I can summarize them here.", ids

    severity_counts = Counter(a.severity for a in alerts)
    module_counts = Counter(a.module for a in alerts)
    top_module, top_count = module_counts.most_common(1)[0]
    share = round(100 * top_count / len(alerts))

    def _c(name: str) -> int:
        return severity_counts.get(name, 0)

    parts = [f"{_c('critical')} critical", f"{_c('high')} high", f"{_c('medium')} medium"]
    return (
        "Here's the current threat picture for your organization:\n\n"
        f"• {len(alerts)} alerts total\n"
        f"• {', '.join(parts)}\n"
        f"• Top category: {top_module} ({share}% of alerts)\n\n"
        "Ask me to show critical alerts or what to investigate first."
    ), ids


async def _reply_critical(db: AsyncSession, organization_id: str) -> tuple[str, list[str]]:
    result = await db.execute(
        select(Alert)
        .where(Alert.organization_id == organization_id, Alert.severity == "critical")
        .order_by(desc(Alert.risk_score))
        .limit(5)
    )
    alerts = list(result.scalars().all())
    ids = [a.id for a in alerts]
    if not alerts:
        return "No critical alerts right now. 🎉", ids
    lines = ["Critical alerts right now:"]
    for i, a in enumerate(alerts, 1):
        lines.append(f"{i}. {a.title} ({a.module}, risk {a.risk_score}, {a.status})")
    lines.append("\nSay 'what should I investigate first?' for a triage order.")
    return "\n".join(lines), ids


async def _reply_mitre(db: AsyncSession, organization_id: str) -> tuple[str, list[str]]:
    alerts = await _load_alerts(db, organization_id)
    technique_counts: Counter[tuple[str, str]] = Counter()
    ids: list[str] = []
    for alert in alerts:
        ids.append(alert.id)
        for technique in alert.mitre or []:
            if isinstance(technique, dict) and technique.get("id"):
                name = str(technique.get("name") or technique["id"])
                technique_counts[(str(technique["id"]), name)] += 1
    if not technique_counts:
        return "No MITRE ATT&CK techniques have been mapped in your alerts yet.", ids
    lines = ["MITRE ATT&CK techniques observed in your alerts:"]
    for (technique_id, name), count in technique_counts.most_common(10):
        lines.append(f"• {technique_id} {name} — {count} alert{'s' if count != 1 else ''}")
    return "\n".join(lines), ids


async def _reply_investigate(db: AsyncSession, organization_id: str) -> tuple[str, list[str]]:
    result = await db.execute(
        select(Alert)
        .where(Alert.organization_id == organization_id, Alert.status.in_(("new", "acknowledged")))
        .order_by(desc(Alert.risk_score))
        .limit(3)
    )
    alerts = list(result.scalars().all())
    ids = [a.id for a in alerts]
    if not alerts:
        return "No open alerts to investigate — the queue is clear. 🎉", ids
    lines = ["Suggested triage order (highest risk first):"]
    for i, a in enumerate(alerts, 1):
        lines.append(f"{i}. {a.title} — risk {a.risk_score} ({a.severity}, {a.module.replace('_', ' ')}, status: {a.status})")
    return "\n".join(lines), ids


async def chat_with_assistant(
    db: AsyncSession,
    *,
    organization_id: str,
    user_message: str,
    user_id: str = "",
    user_name: str = "",
) -> dict[str, Any]:
    """Answer an analyst message under the strict whitelist policy."""
    intent = classify_intent(user_message)

    if intent == "INTERNAL_PROBE":
        # Probing the assistant is itself observable — audit-log the attempt.
        await audit_service.log_action(
            db,
            organization_id=organization_id,
            user_id=user_id,
            user_name=user_name,
            action="SOC Assistant internal probe refused",
            resource="assistant",
            details=user_message[:200],
        )
        return {"reply": REFUSAL_INTERNAL, "context_used": []}

    if intent == "GREETING":
        reply, context_used = GREETING_REPLY, []
    elif intent == "HELP":
        reply, context_used = HELP_MENU, []
    elif intent == "OPS_STATS":
        reply, context_used = await _reply_summary(db, organization_id)
    elif intent == "OPS_CRITICAL":
        reply, context_used = await _reply_critical(db, organization_id)
    elif intent == "OPS_MITRE":
        reply, context_used = await _reply_mitre(db, organization_id)
    elif intent == "OPS_PRIORITIZE":
        reply, context_used = await _reply_investigate(db, organization_id)
    else:  # OUT_OF_SCOPE
        reply, context_used = REFUSAL_OUT_OF_SCOPE, []

    await audit_service.log_action(
        db,
        organization_id=organization_id,
        user_id=user_id,
        user_name=user_name,
        action="SOC Assistant query",
        resource="assistant",
        details=f"[{intent}] {user_message[:200]}",
    )
    return {"reply": reply, "context_used": context_used}
