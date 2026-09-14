"""Server-mode integration endpoints for external systems.

Email gateways, web proxies, firewalls, SSO providers, and content-moderation
systems call these endpoints to get a synchronous enforcement decision for a
single artifact. The full client-mode detection pipeline is reused (heuristic
detectors -> ML blend -> XAI explanation -> alert), then the alert is evaluated
against the organization's active EnforcementPolicy and the resulting action is
executed (simulated) via the ActionExecutor with a complete audit trail.

Management endpoints (quarantine queue, block lists, approval inbox) arrive in
Phase 3; this module owns the analyze-and-enforce surface only.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.openrouter_client import call_openrouter
from app.ai.prompt_templates import (
    ACCOUNT_TAKEOVER_SYSTEM_PROMPT,
    DEEPFAKE_SYSTEM_PROMPT,
    NETWORK_THREAT_SYSTEM_PROMPT,
    PHISHING_SYSTEM_PROMPT,
    URL_SYSTEM_PROMPT,
    format_account_takeover_user_prompt,
    format_deepfake_user_prompt,
    format_network_user_prompt,
    format_phishing_user_prompt,
    format_url_user_prompt,
)
from app.core.mode_detector import ModeContext, resolve_mode
from app.core.security import TenantContext, require_role
from app.db.models import EnforcementPolicy, Event
from app.db.session import get_db
from app.schemas.integrations import (
    AuthLoginAnalyzeRequest,
    EmailGatewayAnalyzeRequest,
    IntegrationDecisionResponse,
    MediaAnalyzeRequest,
    NetworkFlowAnalyzeRequest,
    UrlProxyAnalyzeRequest,
)
from app.services.account_takeover_detector import analyze_auth_log_heuristics
from app.services.action_executor import action_executor, refine_action_for_module
from app.services.alert_service import create_alert
from app.services.enforcement_engine import enforcement_engine
from app.services.ml_inference import score_with_ml
from app.services.network_threat_detector import analyze_network_heuristics
from app.services.phishing_detector import analyze_email_heuristics
from app.services.scoring_service import get_severity
from app.services.url_detector import analyze_url_heuristics

logger = logging.getLogger("cyberguard.integrations")

router = APIRouter(prefix="/integrations", tags=["Integrations"])


async def _resolve_policy(
    db: AsyncSession,
    organization_id: str,
    policy_level: Optional[str] = None,
) -> EnforcementPolicy:
    """Fetch the org's active policy, honouring an optional level hint
    ('strict' | 'balanced' | 'permissive') matched against the policy name."""
    result = await db.execute(
        select(EnforcementPolicy).where(
            EnforcementPolicy.organization_id == organization_id,
            EnforcementPolicy.is_active.is_(True),
        )
    )
    policies = result.scalars().all()
    if not policies:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No active enforcement policy found for organization {organization_id}",
        )
    if policy_level:
        for policy in policies:
            if policy.name.lower().startswith(policy_level.lower()):
                return policy
    return policies[0]


async def _run_integration_pipeline(
    db: AsyncSession,
    tenant: TenantContext,
    mode_ctx: ModeContext,
    *,
    event_type: str,
    module: str,
    source: str,
    raw_data: dict[str, Any],
    indicators: list[dict[str, Any]],
    system_prompt: str,
    user_prompt_builder: Callable[[dict, list, int, str], str],
    policy_level: Optional[str] = None,
    risk_score_override: Optional[int] = None,
) -> IntegrationDecisionResponse:
    """Shared server-mode pipeline: persist event, score, explain, alert,
    evaluate the enforcement policy, execute the action, return the decision."""

    event = Event(
        organization_id=tenant.organization_id,
        owner_user_id=tenant.owner_user_id,
        event_type=event_type,
        source=source,
        raw_data=raw_data,
        status="analyzing",
        created_by=tenant.user_id,
    )
    db.add(event)
    await db.commit()

    if risk_score_override is not None:
        # Upstream confidence scales (e.g. moderation pipelines) are passed
        # through directly instead of the heuristic weight sum, whose 0-40
        # range could never reach the deepfake enforcement bands.
        hybrid_score = max(0, min(100, int(risk_score_override)))
    else:
        _heuristic_score, hybrid_score, _ml_probability = score_with_ml(indicators)
    severity = get_severity(hybrid_score)
    user_prompt = user_prompt_builder(raw_data, indicators, hybrid_score, severity)

    llm_output = await call_openrouter(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        module=module,
        indicators=indicators,
        raw_data=raw_data,
        risk_score=hybrid_score,
    )

    alert = await create_alert(
        db,
        tenant=tenant,
        created_by=tenant.user_id,
        event_id=event.id,
        module=module,
        raw_data=raw_data,
        indicators=indicators,
        score=hybrid_score,
        severity=severity,
        llm_output=llm_output,
    )

    policy = await _resolve_policy(db, tenant.organization_id, policy_level)
    decision = enforcement_engine.evaluate(
        alert=alert,
        policy=policy,
        mode=mode_ctx.mode,
        request_auto_execute=mode_ctx.auto_execute,
    )

    # Policy verbs are platform-agnostic; refine to the module-specific action
    # (e.g. "block" + phishing -> "quarantine_email").
    action_type = refine_action_for_module(decision.action_type, module)

    execution = await action_executor.execute(
        db=db,
        alert=alert,
        action_type=action_type,
        execution_mode=mode_ctx.mode.value,
        raw_data=raw_data,
        policy_id=policy.id,
        organization_id=tenant.organization_id,
        event_id=event.id,
        triggered_by="api",
        triggered_by_id=tenant.user_id,
        auto_execute=decision.auto_execute,
    )

    execution_result = execution.execution_result or {}
    return IntegrationDecisionResponse(
        decision=action_type.upper(),
        alert_id=alert.id,
        risk_score=alert.risk_score,
        severity=alert.severity,
        threat_type=alert.threat_type,
        explanation=alert.explanation,
        mitre_techniques=alert.mitre,
        action_executed=execution.status == "success",
        execution_id=execution.id,
        execution_status=execution.status,
        quarantine_id=execution_result.get("quarantine_id"),
        block_id=execution_result.get("block_id"),
        requires_approval=decision.requires_approval,
        approval_url=f"/alerts/{alert.id}" if decision.requires_approval else None,
        policy_id=policy.id,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _mode_ctx(request_mode: str, request_auto_execute: bool) -> ModeContext:
    return resolve_mode(
        explicit_mode=request_mode,
        source="api_integration",
        auto_execute=request_auto_execute,
    )


# --- Email Gateway -----------------------------------------------------------


@router.post("/email-gateway/analyze", response_model=IntegrationDecisionResponse)
async def analyze_email_gateway(
    request: EmailGatewayAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> IntegrationDecisionResponse:
    """Analyze an inbound email for an email gateway and enforce the policy verdict."""
    raw_data: dict[str, Any] = {
        "sender": request.sender,
        "recipient": request.recipient,
        "subject": request.subject,
        "body": request.body,
        "headers": request.headers or {},
        "attachments": request.attachments or [],
        "email_id": request.email_id,
    }
    indicators = await asyncio.to_thread(
        analyze_email_heuristics,
        sender=request.sender,
        subject=request.subject,
        body=request.body,
    )
    return await _run_integration_pipeline(
        db,
        tenant,
        _mode_ctx(request.mode, request.auto_execute),
        event_type="phishing_email",
        module="phishing",
        source="email_gateway",
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=PHISHING_SYSTEM_PROMPT,
        user_prompt_builder=format_phishing_user_prompt,
        policy_level=request.enforcement_policy,
    )


# --- URL / Web Proxy ---------------------------------------------------------


@router.post("/url-proxy/analyze", response_model=IntegrationDecisionResponse)
async def analyze_url_proxy(
    request: UrlProxyAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> IntegrationDecisionResponse:
    """Analyze a URL for a web proxy and enforce the policy verdict."""
    raw_data: dict[str, Any] = {
        "url": request.url,
        "user_agent": request.user_agent,
        "source_ip": request.source_ip,
        "request_id": request.request_id,
    }
    indicators = await asyncio.to_thread(analyze_url_heuristics, request.url)
    return await _run_integration_pipeline(
        db,
        tenant,
        _mode_ctx(request.mode, request.auto_execute),
        event_type="malicious_url",
        module="url",
        source="proxy",
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=URL_SYSTEM_PROMPT,
        user_prompt_builder=lambda _data, ind, score, sev: format_url_user_prompt(
            request.url, ind, score, sev
        ),
        policy_level=request.enforcement_policy,
    )


# --- Network / Firewall ------------------------------------------------------


@router.post("/network/analyze-flow", response_model=IntegrationDecisionResponse)
async def analyze_network_flow(
    request: NetworkFlowAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> IntegrationDecisionResponse:
    """Analyze a network flow for a firewall and enforce the policy verdict."""
    flow: dict[str, Any] = {
        "source_ip": request.source_ip,
        "destination_ip": request.destination_ip,
        "port": request.port,
        "protocol": request.protocol,
        "bytes_transferred": request.bytes_transferred,
        "flow_id": request.flow_id,
    }
    api_logs = request.api_logs or []
    raw_data: dict[str, Any] = {**flow, "api_logs": api_logs}
    indicators = await asyncio.to_thread(
        analyze_network_heuristics, flows=[flow], api_logs=api_logs
    )
    return await _run_integration_pipeline(
        db,
        tenant,
        _mode_ctx(request.mode, request.auto_execute),
        event_type="network_flow",
        module="network",
        source="firewall",
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=NETWORK_THREAT_SYSTEM_PROMPT,
        user_prompt_builder=lambda _data, ind, score, sev: format_network_user_prompt(
            [flow], api_logs, ind, score, sev
        ),
        policy_level=request.enforcement_policy,
    )


# --- Authentication / SSO ----------------------------------------------------


@router.post("/auth/analyze-login", response_model=IntegrationDecisionResponse)
async def analyze_auth_login(
    request: AuthLoginAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> IntegrationDecisionResponse:
    """Analyze a login attempt for an SSO/IdP and enforce the policy verdict.

    The IdP may optionally attach recent login history (`recent_events`) so the
    ATO heuristics (impossible travel, failed bursts, success-after-failures)
    can correlate the current attempt against prior activity."""
    current_event: dict[str, Any] = {
        "user": request.user_id,
        "ip": request.source_ip,
        "location": request.location,
        "device": request.device_fingerprint,
        "status": "success",
        "timestamp": request.timestamp,
    }
    events = [current_event] + [e for e in (request.recent_events or []) if isinstance(e, dict)]
    raw_data: dict[str, Any] = {
        "user_id": request.user_id,
        "source_ip": request.source_ip,
        "user_agent": request.user_agent,
        "device_fingerprint": request.device_fingerprint,
        "login_attempt_id": request.login_attempt_id,
        "location": request.location,
        "timestamp": request.timestamp,
        "events": events,
    }
    indicators = await asyncio.to_thread(analyze_auth_log_heuristics, events)
    return await _run_integration_pipeline(
        db,
        tenant,
        _mode_ctx(request.mode, request.auto_execute),
        event_type="account_takeover",
        module="account_takeover",
        source="sso",
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=ACCOUNT_TAKEOVER_SYSTEM_PROMPT,
        user_prompt_builder=lambda _data, ind, score, sev: format_account_takeover_user_prompt(
            events, ind, score, sev
        ),
        policy_level=request.enforcement_policy,
    )


# --- Media / Content Moderation ----------------------------------------------


@router.post("/media/analyze", response_model=IntegrationDecisionResponse)
async def analyze_media_integration(
    request: MediaAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> IntegrationDecisionResponse:
    """Analyze media metadata for a content-moderation system and enforce the
    policy verdict. Binary uploads stay on /analysis/media (full forensics);
    this metadata-only surface lets moderation queues pre-screen by reference."""
    metadata = request.metadata or {}
    raw_data: dict[str, Any] = {
        "media_type": request.media_type,
        "file_url": request.file_url,
        "file_hash": request.file_hash,
        "metadata": metadata,
        "media_id": request.media_id,
    }

    indicators: list[dict[str, Any]] = []
    confidence = metadata.get("manipulation_confidence")
    if isinstance(confidence, (int, float)) and 0 <= confidence <= 1:
        indicators.append({
            "type": "metadata_manipulation_confidence",
            "value": f"{confidence:.2f}",
            "severity": "critical" if confidence >= 0.85 else "high" if confidence >= 0.6 else "medium",
            "description": f"Upstream moderation pipeline reports manipulation confidence {confidence:.2f}.",
        })
    elif metadata.get("manipulation_detected"):
        indicators.append({
            "type": "metadata_manipulation_flag",
            "value": "manipulation_detected",
            "severity": "high",
            "description": "Upstream moderation pipeline flagged the media as manipulated.",
        })

    forensics_summary = {
        "method": "integration_metadata",
        "simulated": False,
        "media_type": request.media_type,
        "manipulation_probability": confidence if isinstance(confidence, (int, float)) else None,
    }
    return await _run_integration_pipeline(
        db,
        tenant,
        _mode_ctx(request.mode, request.auto_execute),
        event_type="deepfake_media",
        module="deepfake",
        source="content_moderation",
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=DEEPFAKE_SYSTEM_PROMPT,
        user_prompt_builder=lambda _data, ind, score, sev: format_deepfake_user_prompt(
            forensics_summary, risk_score=score, severity=sev
        ),
        policy_level=request.enforcement_policy,
        risk_score_override=round(confidence * 100)
        if isinstance(confidence, (int, float)) and 0 <= confidence <= 1
        else None,
    )
