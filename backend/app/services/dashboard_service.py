"""Dashboard summary service using Async SQLAlchemy."""

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.security import TenantContext, tenant_criteria
from app.db.models import Alert, Event, Incident

logger = logging.getLogger("cyberguard.dashboard")

SEVERITY_ORDER = ["safe", "low", "medium", "high", "critical"]
SEVERITY_COLORS = {
    "safe": "#10b981",
    "low": "#eab308",
    "medium": "#f59e0b",
    "high": "#f97316",
    "critical": "#ef4444",
}
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}
MODULE_ORDER = [
    "phishing",
    "url",
    "impersonation",
    "deepfake",
    "account_takeover",
    "network",
    "api_abuse",
]
INCIDENT_STATUSES = ["open", "investigating", "contained", "closed"]
TIMELINE_HOURS = 24


def _build_attack_timeline(
    alerts: list[Alert], events: list[Event], now: datetime
) -> list[dict[str, Any]]:
    """Bucket alerts and events into the last 24 hourly slots."""
    buckets: dict[str, dict[str, Any]] = {}
    for hours_ago in range(TIMELINE_HOURS - 1, -1, -1):
        slot_start = (now - timedelta(hours=hours_ago)).replace(
            minute=0, second=0, microsecond=0
        )
        key = slot_start.strftime("%Y-%m-%d %H")
        buckets[key] = {
            "hour": slot_start.strftime("%H:00"),
            "threats": 0,
            "events": 0,
        }

    for alert in alerts:
        created_at = alert.created_at
        if created_at is None:
            continue
        key = created_at.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H")
        if key in buckets:
            buckets[key]["threats"] += 1

    for event in events:
        created_at = event.created_at
        if created_at is None:
            continue
        key = created_at.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H")
        if key in buckets:
            buckets[key]["events"] += 1

    return list(buckets.values())


def _top_targeted_users(alerts: list[Alert]) -> list[dict[str, Any]]:
    """Group alerts by target_user."""
    stats: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        target_user = alert.target_user
        if not target_user:
            continue
        entry = stats.setdefault(
            target_user, {"attacks": 0, "last_attack": alert.created_at.isoformat() if alert.created_at else None}
        )
        entry["attacks"] += 1
    ranked = sorted(stats.items(), key=lambda item: item[1]["attacks"], reverse=True)
    return [
        {"user": user, "attacks": entry["attacks"], "last_attack": entry["last_attack"]}
        for user, entry in ranked[:5]
    ]


def _top_targeted_services(alerts: list[Alert]) -> list[dict[str, Any]]:
    """Group alerts by target_service with the highest severity seen."""
    stats: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        target_service = alert.target_service
        if not target_service:
            continue
        entry = stats.setdefault(
            target_service, {"attacks": 0, "risk_rank": -1, "risk_level": None}
        )
        entry["attacks"] += 1
        rank = SEVERITY_RANK.get(alert.severity, -1)
        if rank > entry["risk_rank"]:
            entry["risk_rank"] = rank
            entry["risk_level"] = alert.severity
    ranked = sorted(stats.items(), key=lambda item: item[1]["attacks"], reverse=True)
    return [
        {
            "service": service,
            "attacks": entry["attacks"],
            "risk_level": entry["risk_level"],
        }
        for service, entry in ranked[:5]
    ]


async def get_dashboard_summary(db: AsyncSession, tenant: TenantContext) -> dict[str, Any]:
    """Build the complete dashboard summary for the active tenant."""
    # Load alerts
    alerts_res = await db.execute(
        select(Alert)
        .options(selectinload(Alert.recommended_actions))
        .where(tenant_criteria(Alert, tenant))
        .order_by(desc(Alert.created_at))
    )
    alerts = list(alerts_res.scalars().all())

    # Load events
    events_res = await db.execute(
        select(Event).where(tenant_criteria(Event, tenant))
    )
    events = list(events_res.scalars().all())

    # Load incidents
    incidents_res = await db.execute(
        select(Incident).where(tenant_criteria(Incident, tenant))
    )
    incidents = list(incidents_res.scalars().all())

    # Counts
    module_counts = Counter(alert.module for alert in alerts)
    severity_counts = Counter(alert.severity for alert in alerts)

    risk_distribution = [
        {
            "name": severity,
            "value": severity_counts.get(severity, 0),
            "color": SEVERITY_COLORS[severity],
        }
        for severity in SEVERITY_ORDER
    ]
    threat_categories = [
        {"name": module, "count": module_counts.get(module, 0)}
        for module in MODULE_ORDER
    ]

    incident_summary = {status_name: 0 for status_name in INCIDENT_STATUSES}
    for incident in incidents:
        if incident.status in incident_summary:
            incident_summary[incident.status] += 1

    recent_alerts_serialized = []
    for alert in alerts[:10]:
        recent_alerts_serialized.append(
            {
                "id": alert.id,
                "title": alert.title,
                "module": alert.module,
                "threat_type": alert.threat_type,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "status": alert.status,
                "summary": alert.summary,
                "target_user": alert.target_user,
                "target_service": alert.target_service,
                "source_ip": alert.source_ip,
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
                "recommended_actions": [
                    {
                        "id": act.id,
                        "action": act.action,
                        "description": act.description,
                        "automation_level": act.automation_level,
                        "requires_approval": act.requires_approval,
                        "priority": act.priority,
                        "executed": act.executed,
                    }
                    for act in alert.recommended_actions
                ],
            }
        )

    return {
        "total_events_analyzed": len(events),
        "threats_detected": len(alerts),
        "phishing_attempts": module_counts.get("phishing", 0),
        "impersonation_attempts": module_counts.get("impersonation", 0),
        "suspected_deepfakes": module_counts.get("deepfake", 0),
        "account_takeover_attempts": module_counts.get("account_takeover", 0),
        "network_threats": module_counts.get("network", 0),
        "api_abuse_attempts": module_counts.get("api_abuse", 0),
        "risk_distribution": risk_distribution,
        "threat_categories": threat_categories,
        "attack_timeline": _build_attack_timeline(alerts, events, datetime.now(timezone.utc)),
        "top_targeted_users": _top_targeted_users(alerts),
        "top_targeted_services": _top_targeted_services(alerts),
        "recent_alerts": recent_alerts_serialized,
        "incident_summary": incident_summary,
    }
