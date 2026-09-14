"""ORG-2: Splunk-style live log analysis for organizations.

Endpoints (all org-scoped):

- ``POST /org/{org_id}/logs/ingest``  — API-key authenticated (gateway).
  Auto-detects the log type (auth | network | app) by payload shape, runs
  the matching detector synchronously (no LLM on the ingest path), stores
  the row in ``org_log_events``, and promotes medium+ findings to an
  org-scoped Event + Alert so dashboards and realtime see them.
- ``GET  /org/{org_id}/logs/stream``  — last 100 events (initial load);
  live updates arrive via Supabase ``postgres_changes`` on
  ``org_log_events`` (publication wiring in migration 0009).
- ``POST /org/{org_id}/logs/{log_id}/action`` — manual analyst action
  (block_ip | revoke_session | isolate_host | escalate_incident |
  mark_safe): records the decision on the log row and writes an audit-log
  entry with the acting analyst. ORG-3 wires real enforcement targets.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, PermissionDeniedError, ValidationError
from app.core.permissions import OrgRole, require_org_role
from app.core.security import TenantContext
from app.db.admin import _get_admin_session_maker
from app.db.models import (
    AuditLog,
    Event,
    Organization,
    OrganizationMember,
    OrgLogEvent,
)
from app.db.session import get_db
from app.schemas.org_dashboards import (
    LogActionRequest,
    LogActionResponse,
    LogIngestRequest,
    LogIngestResponse,
    OrgLogEventResponse,
)
from app.services.alert_service import create_alert
from app.services.api_key_service import get_org_from_api_key
from app.services.org_log_analyzer import analyze_log

logger = logging.getLogger("cyberguard.org_logs")

router = APIRouter(prefix="/org", tags=["Org Logs"])

STREAM_DEFAULT = 100
STREAM_MAX = 500

# medium+ log findings are promoted to the alert plane
ALERT_PROMOTION_SCORE = 40

MODULE_FOR_LOG_TYPE = {
    "auth": "account_takeover",
    "network": "network",
    "app": "api_abuse",
}

EVENT_TYPE_FOR_LOG_TYPE = {
    "auth": "log_auth",
    "network": "log_network",
    "app": "log_app",
}

VALID_ACTIONS = {"block_ip", "revoke_session", "escalate_incident", "mark_safe", "isolate_host"}


def _org_tenant(org: Organization) -> TenantContext:
    """Tenant context for gateway log ingestion (org service identity)."""
    return TenantContext(
        user_id=org.owner_id,
        owner_user_id=org.owner_id,
        organization_id=org.id,
        organization_name=org.name,
        role=OrgRole.ADMIN.value,
        is_single_user=False,
    )


@router.post("/{org_id}/logs/ingest", response_model=LogIngestResponse)
async def ingest_org_log(
    org_id: str,
    payload: LogIngestRequest,
    org: Organization = Depends(get_org_from_api_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Ingest + auto-analyze one log payload (gateway, API-key auth)."""
    if org.id != org_id:
        raise PermissionDeniedError("API key does not belong to this organization")

    result = analyze_log(payload.data, log_type=payload.log_type)
    log_event = OrgLogEvent(
        organization_id=org.id,
        log_type=result["log_type"],
        raw_data=payload.data if isinstance(payload.data, (dict, list)) else {"value": str(payload.data)},
        analysis_result=result,
        severity=result["severity"],
        created_by=f"api_key:{org.id}",
    )
    db.add(log_event)
    await db.flush()

    alert_id: str | None = None
    if result["risk_score"] >= ALERT_PROMOTION_SCORE:
        tenant = _org_tenant(org)
        event = Event(
            id=str(uuid.uuid4()),
            organization_id=org.id,
            owner_user_id=org.owner_id,
            event_type=EVENT_TYPE_FOR_LOG_TYPE.get(result["log_type"], "log_anomaly"),
            source="gateway",
            raw_data={"log_id": log_event.id, "summary": result["summary"]},
            status="completed",
            created_by=f"api_key:{org.id}",
        )
        db.add(event)
        await db.flush()
        alert = await create_alert(
            db,
            tenant=tenant,
            event_id=event.id,
            module=MODULE_FOR_LOG_TYPE.get(result["log_type"], "network"),
            raw_data={"subject": result["summary"], "log_id": log_event.id},
            indicators=result["indicators"],
            score=result["risk_score"],
            severity=result["severity"],
            llm_output={
                "explanation": result["summary"],
                "mitre_techniques": result["mitre_techniques"],
            },
            created_by=f"api_key:{org.id}",
        )
        alert_id = alert.id

    await db.commit()
    return LogIngestResponse(
        status="analyzed",
        log_id=log_event.id,
        log_type=result["log_type"],
        result=result,
        alert_id=alert_id,
    )


@router.get("/{org_id}/logs/stream", response_model=list[OrgLogEventResponse])
async def stream_org_logs(
    org_id: str,
    limit: int = Query(default=STREAM_DEFAULT, ge=1, le=STREAM_MAX),
    severity: str | None = Query(default=None),
    log_type: str | None = Query(default=None),
    member: OrganizationMember = Depends(require_org_role(OrgRole.VIEWER)),
) -> Any:
    """Latest ingested logs (newest first) — the initial load for the live
    stream view. Live updates arrive via Supabase postgres_changes; clients
    without realtime fall back to re-polling this endpoint."""
    predicates = [OrgLogEvent.organization_id == org_id]
    if severity:
        if severity not in {"safe", "low", "medium", "high", "critical"}:
            raise ValidationError("invalid severity filter")
        predicates.append(OrgLogEvent.severity == severity)
    if log_type:
        if log_type not in {"auth", "network", "app"}:
            raise ValidationError("invalid log_type filter")
        predicates.append(OrgLogEvent.log_type == log_type)

    async with _get_admin_session_maker()() as db:
        result = await db.execute(
            select(OrgLogEvent)
            .where(*predicates)
            .order_by(OrgLogEvent.created_at.desc())
            .limit(limit)
        )
        events = result.scalars().all()

    return [
        OrgLogEventResponse(
            id=e.id,
            log_type=e.log_type,
            severity=e.severity,
            raw_data=e.raw_data or {},
            analysis_result=e.analysis_result or {},
            manual_action_taken=e.manual_action_taken,
            acted_by=e.acted_by,
            acted_at=e.acted_at,
            created_at=e.created_at,
        )
        for e in events
    ]


@router.post("/{org_id}/logs/{log_id}/action", response_model=LogActionResponse)
async def take_log_action(
    org_id: str,
    log_id: str,
    payload: LogActionRequest,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Manual analyst action on a log row (analyst+). Records the decision
    and writes an audit-log entry; real enforcement targets (firewall/IP
    blocklists) are wired in ORG-3+."""
    if payload.action not in VALID_ACTIONS:
        raise ValidationError(f"action must be one of {sorted(VALID_ACTIONS)}")

    log_event = await db.get(OrgLogEvent, log_id)
    if log_event is None or log_event.organization_id != org_id:
        raise NotFoundError("Log event", log_id)
    if payload.action == "mark_safe" and log_event.manual_action_taken:
        raise ValidationError(f"Log already resolved via '{log_event.manual_action_taken}'")

    now = datetime.now(timezone.utc)
    log_event.manual_action_taken = payload.action
    log_event.acted_by = member.user_id
    log_event.acted_at = now
    await db.flush()

    db.add(AuditLog(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        owner_user_id=member.user_id,
        user_id=member.user_id,
        actor_type="user",
        action=f"org_log:{payload.action}",
        resource=f"org_log_events/{log_id}",
        details=(payload.note or payload.target or "").strip() or None,
    ))
    await db.commit()

    return LogActionResponse(
        log_id=log_id,
        action=payload.action,
        taken_by=member.user_id,
        taken_at=now,
    )
