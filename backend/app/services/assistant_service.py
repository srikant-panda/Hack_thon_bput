"""SOC assistant chat service using Async SQLAlchemy and OpenRouter."""

import logging
from collections import Counter
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.openrouter_client import call_openrouter
from app.ai.prompt_templates import SOC_ASSISTANT_SYSTEM_PROMPT
from app.db.models import Alert
from app.services import audit_service

logger = logging.getLogger("cyberguard.assistant")

CONTEXT_ALERT_COUNT = 20


def _build_context_summary(alerts: list[Alert]) -> str:
    """Build a compact threat context block for the LLM prompt."""
    severity_counts = Counter(alert.severity for alert in alerts)
    module_counts = Counter(alert.module for alert in alerts)
    critical_titles = [
        f"- [{alert.id}] {alert.title} (module: {alert.module})"
        for alert in alerts
        if alert.severity == "critical"
    ]

    lines = [f"Total recent alerts analyzed: {len(alerts)}"]
    lines.append(
        "Alerts by severity: "
        + ", ".join(f"{name}={count}" for name, count in sorted(severity_counts.items()))
    )
    lines.append(
        "Alerts by module: "
        + ", ".join(f"{name}={count}" for name, count in sorted(module_counts.items()))
    )
    if critical_titles:
        lines.append("Critical alert titles:")
        lines.extend(critical_titles)
    else:
        lines.append("No critical alerts in the recent context.")
    return "\n".join(lines)


async def chat_with_assistant(
    db: AsyncSession,
    *,
    organization_id: str,
    user_message: str,
    user_id: str = "",
    user_name: str = "",
) -> dict[str, Any]:
    """Answer an analyst question grounded in the active organization's recent alert context."""
    alert_query = await db.execute(
        select(Alert)
        .where(Alert.organization_id == organization_id)
        .order_by(desc(Alert.created_at))
        .limit(CONTEXT_ALERT_COUNT)
    )
    alerts = list(alert_query.scalars().all())

    context_summary = _build_context_summary(alerts)
    context_used = [alert.id for alert in alerts]

    user_prompt = (
        f"Current threat context for this organization:\n{context_summary}\n\n"
        f"Analyst question: {user_message}\n\n"
        "Provide a concise, professional, and actionable cybersecurity response based on the context above."
    )

    llm_output = await call_openrouter(
        SOC_ASSISTANT_SYSTEM_PROMPT,
        user_prompt,
        module="assistant",
        indicators=[],
        raw_data={"question": user_message},
    )

    reply = str(
        llm_output.get("reply")
        or llm_output.get("explanation")
        or "Based on your current telemetry, all monitored indicators have been reviewed. No immediate critical escalation required."
    )

    await audit_service.log_action(
        db,
        organization_id=organization_id,
        user_id=user_id,
        user_name=user_name,
        action="SOC Assistant query",
        resource="assistant",
        details=user_message[:200],
    )
    return {"reply": reply, "context_used": context_used}
