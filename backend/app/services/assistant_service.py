"""SOC assistant chat service — intent routing, data-backed answers, LLM escalation.

The assistant is a conversational SOC helper, NOT an artifact scanner: chat text
is classified by intent first and never passed through the threat-detection
heuristics. Data intents (summary, critical alerts, MITRE, triage) query the
caller's organization data directly; free-text security questions go to the LLM
engine, with the help menu (never artifact-analysis output) as the fallback.
"""

import logging
import re
from collections import Counter
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_client import call_llm
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
    "Any other security question goes to the AI engine (with live alert context). "
    "I answer from your organization's data only — I never invent numbers."
)

GREETING_REPLY = (
    "Hello Analyst 👋 I'm your SOC Assistant. I can summarize today's threats, "
    "show critical alerts, list MITRE techniques, or tell you what to "
    "investigate first. What do you need?"
)

# Ordered: first match wins. Greeting is anchor-anchored so questions that
# merely contain these substrings are not misrouted.
_INTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("greeting", re.compile(r"^\s*(hi|helo+|hello|hey|yo|greetings|good\s*(morning|afternoon|evening))\b", re.I)),
    ("help", re.compile(r"\b(help|what can you do|commands|capabilities|options)\b", re.I)),
    ("mitre_list", re.compile(r"\b(mitre|att&ck|techniques?)\b", re.I)),
    ("summarize_threats", re.compile(r"\b(summar\w*|overview|sitrep|situation report|threat picture|current threats|today'?s? threats)\b", re.I)),
    ("critical_alerts", re.compile(r"\b(critical|worst|severe)\b", re.I)),
    ("investigate_first", re.compile(r"\b(investigate|priorit\w*|triage|what next|first)\b", re.I)),
]


def classify_intent(message: str) -> str:
    """Route a chat message to an intent. Anything unmatched is a general question."""
    for intent, pattern in _INTENT_PATTERNS:
        if pattern.search(message):
            return intent
    return "general_question"


async def _load_alerts(db: AsyncSession, tenant, limit: int = 500) -> list[Alert]:
    from app.core.security import tenant_criteria

    result = await db.execute(
        select(Alert)
        .where(tenant_criteria(Alert, tenant))
        .order_by(desc(Alert.created_at))
        .limit(limit)
    )
    return list(result.scalars().all())


async def _reply_summary(db: AsyncSession, tenant) -> tuple[str, list[str]]:
    alerts = await _load_alerts(db, tenant)
    ids = [a.id for a in alerts]
    if not alerts:
        return "No alerts have been recorded for your workspace yet. Once detections fire, I can summarize them here.", ids

    severity_counts = Counter(a.severity for a in alerts)
    module_counts = Counter(a.module for a in alerts)
    top_module, top_count = module_counts.most_common(1)[0]
    share = round(100 * top_count / len(alerts))

    def _c(name: str) -> int:
        return severity_counts.get(name, 0)

    parts = [f"{_c('critical')} critical", f"{_c('high')} high", f"{_c('medium')} medium"]
    return (
        "Here's the current threat picture for your workspace:\n\n"
        f"• {len(alerts)} alerts total\n"
        f"• {', '.join(parts)}\n"
        f"• Top category: {top_module} ({share}% of alerts)\n\n"
        "Ask me to show critical alerts or what to investigate first."
    ), ids


async def _reply_critical(db: AsyncSession, tenant) -> tuple[str, list[str]]:
    from app.core.security import tenant_criteria

    result = await db.execute(
        select(Alert)
        .where(tenant_criteria(Alert, tenant), Alert.severity == "critical")
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


async def _reply_mitre(db: AsyncSession, tenant) -> tuple[str, list[str]]:
    alerts = await _load_alerts(db, tenant)
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


async def _reply_investigate(db: AsyncSession, tenant) -> tuple[str, list[str]]:
    from app.core.security import tenant_criteria

    result = await db.execute(
        select(Alert)
        .where(tenant_criteria(Alert, tenant), Alert.status.in_(("new", "acknowledged")))
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


async def _reply_general_question(
    db: AsyncSession,
    tenant,
    user_message: str,
) -> tuple[str, list[str]]:
    """Free-text questions go to the LLM with org context. The no-key / failed
    fallback is the help menu — never the artifact-analysis heuristic output."""
    alerts = await _load_alerts(db, tenant, CONTEXT_ALERT_COUNT)
    ids = [a.id for a in alerts]

    severity_counts = Counter(a.severity for a in alerts)
    top_severity = "none"
    for band in ("critical", "high", "medium", "low"):
        if severity_counts.get(band):
            top_severity = band
            break

    system_prompt = (
        "You are CYBERGUARD's SOC Assistant. Answer concisely (max 6 sentences). "
        f"Context: the organization has {len(alerts)} recent alerts, top severity {top_severity}. "
        "If the question is unrelated to security, say so politely. "
        'Respond ONLY with a JSON object: {"reply": "<your answer>"}'
    )
    user_prompt = f"Analyst question: {user_message}"

    llm_output = await call_llm(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        module="assistant",
        indicators=[],
        raw_data={"question": user_message},
        risk_score=0,
    )

    reply = llm_output.get("reply")
    if not reply:
        # No usable LLM answer (no keys, all providers exhausted, or unparseable).
        # The artifact-analysis heuristic output must never reach the chat.
        return HELP_MENU, ids
    return str(reply), ids


async def chat_with_assistant(
    db: AsyncSession,
    *,
    tenant,
    user_message: str,
    user_id: str = "",
    user_name: str = "",
) -> dict[str, Any]:
    """Answer an analyst message with intent routing and tenant-scoped data."""
    intent = classify_intent(user_message)

    if intent == "greeting":
        reply, context_used = GREETING_REPLY, []
    elif intent == "help":
        reply, context_used = HELP_MENU, []
    elif intent == "summarize_threats":
        reply, context_used = await _reply_summary(db, tenant)
    elif intent == "critical_alerts":
        reply, context_used = await _reply_critical(db, tenant)
    elif intent == "mitre_list":
        reply, context_used = await _reply_mitre(db, tenant)
    elif intent == "investigate_first":
        reply, context_used = await _reply_investigate(db, tenant)
    else:
        reply, context_used = await _reply_general_question(db, tenant, user_message)

    await audit_service.log_action(
        db,
        tenant=tenant,
        user_id=user_id,
        user_name=user_name,
        action="SOC Assistant query",
        resource="assistant",
        details=f"[{intent}] {user_message[:200]}",
    )
    return {"reply": reply, "context_used": context_used}
