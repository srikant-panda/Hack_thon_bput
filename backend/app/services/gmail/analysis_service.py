"""Email analysis service for threat detection, ML inference, and result persistence."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ProcessedEmail, ScanResult
from app.services.impersonation_detector import analyze_impersonation_heuristics
from app.services.ml_inference import (
    ml_indicator,
    predict_email,
    predict_url,
    split_ml_indicator,
)
from app.services.phishing_detector import analyze_email_heuristics
from app.services.realtime_notifier import notify_email_processed
from app.services.scoring_service import (
    SEVERITY_WEIGHTS,
    calculate_score,
    get_severity,
)
from app.services.url_detector import analyze_url_heuristics

logger = logging.getLogger("cyberguard.gmail.analysis")


def monotonic_blend(heuristic: float, ml: Optional[float]) -> float:
    """Monotonic blend formula: final_score = max(heuristic, 0.45*heuristic + 0.55*ml).

    Ensures ML probability may elevate a heuristic verdict, but never lower it.
    """
    if ml is None:
        return round(heuristic, 3)
    blended = 0.45 * heuristic + 0.55 * ml
    return round(max(heuristic, blended), 3)


def _indicator_weight(indicator: dict[str, Any]) -> float:
    sev = str(indicator.get("severity", "")).lower()
    return float(SEVERITY_WEIGHTS.get(sev, indicator.get("weight", 0)))


def _build_explanation(
    sender: str,
    subject: str,
    risk_score: float,
    severity: str,
    text_score: float,
    url_score: float,
    impers_score: float,
    top_indicators: list[dict[str, Any]],
) -> str:
    verdicts = [
        f"phishing={text_score:.2f}",
        f"url={url_score:.2f}",
        f"impersonation={impers_score:.2f}",
    ]
    evidence = [
        f"'{i.get('description') or i.get('type')}'"
        for i in top_indicators[:4]
        if i.get("description") or i.get("type")
    ]
    evidence_str = "; ".join(evidence) if evidence else "No suspicious indicators were found."
    return (
        f"Message '{subject or '(no subject)'}' from '{sender}' was evaluated by CyberGuard threat analysis engines: "
        f"{', '.join(verdicts)}. The combined threat score is {round(risk_score * 100)}/100 ({severity}). "
        f"Strongest evidence: {evidence_str}"
    )


async def process_email_analysis(
    db: AsyncSession,
    processed_email_id: str,
    supabase_client: Optional[Any] = None,
) -> dict[str, Any]:
    """Execute threat detection pipeline, ML inference, and result persistence."""
    # 1. Load processed_email with row lock; verify status == 'fetched'
    stmt = (
        select(ProcessedEmail)
        .where(ProcessedEmail.id == processed_email_id)
        .with_for_update()
    )
    processed_email = (await db.execute(stmt)).scalar_one_or_none()
    if processed_email is None:
        raise ValueError(f"ProcessedEmail not found: {processed_email_id}")

    if processed_email.processing_status != "fetched":
        logger.info(
            "ProcessedEmail %s already in status '%s'; skipping analysis",
            processed_email_id,
            processed_email.processing_status,
        )
        return {
            "processed_email_id": processed_email_id,
            "status": "skipped",
            "reason": f"already_{processed_email.processing_status}",
            "risk_score": processed_email.risk_score or 0.0,
            "classification": processed_email.classification or "unknown",
            "scan_result_id": processed_email.scan_result_id,
        }

    # 2. Transition status -> 'analyzing'
    processed_email.processing_status = "analyzing"
    processed_email.updated_at = datetime.now(timezone.utc)
    await db.commit()

    # 3. Extract normalized email data, urls, body, headers, signals
    signals = dict(processed_email.signals or {})
    norm_email = signals.get("normalized_email") or {}
    subject = norm_email.get("subject") or processed_email.subject or ""
    sender = norm_email.get("sender") or processed_email.sender or ""
    body_text = norm_email.get("body_text") or ""
    urls: list[str] = signals.get("urls") or []
    headers: dict[str, str] = signals.get("headers") or {}
    spf = str(signals.get("spf") or "none")
    dkim = str(signals.get("dkim") or "none")
    dmarc = str(signals.get("dmarc") or "none")

    # 4. Detection Engines & 5. ML Inference
    # --- A. Phishing Analysis ---
    text_indicators = analyze_email_heuristics(sender, subject, body_text)
    heuristic_text_inds, ml_email_prob = split_ml_indicator(text_indicators)
    if ml_email_prob is None:
        ml_email_prob = predict_email("\n".join([sender, subject, body_text]))

    text_heur_score = calculate_score(heuristic_text_inds) / 100.0
    ml_email_score = ml_email_prob if ml_email_prob is not None else 0.0
    text_score = monotonic_blend(text_heur_score, ml_email_prob)

    # --- B. URL Analysis ---
    url_indicators: list[dict[str, Any]] = []
    ml_url_scores: list[float] = []
    url_scores: list[float] = []

    for url in urls:
        u_inds = analyze_url_heuristics(url)
        u_heur, u_ml = split_ml_indicator(u_inds)
        if u_ml is None:
            u_ml = predict_url(url)
        u_heur_score = calculate_score(u_heur) / 100.0
        u_ml_score = u_ml if u_ml is not None else 0.0
        u_final = monotonic_blend(u_heur_score, u_ml)

        url_indicators.extend(u_inds)
        ml_url_scores.append(u_ml_score)
        url_scores.append(u_final)

    url_score = max(url_scores) if url_scores else 0.0
    url_model = max(ml_url_scores) if ml_url_scores else 0.0

    # --- C. Impersonation Analysis ---
    claimed_identity = sender
    if "<" in sender and ">" in sender:
        claimed_identity = sender.split("<", 1)[0].strip().strip('"')
    impers_indicators = analyze_impersonation_heuristics(
        f"{subject}\n{body_text}", claimed_identity
    )
    impers_score = calculate_score(impers_indicators) / 100.0

    # --- D. Authentication Signals (SPF/DKIM/DMARC) ---
    auth_indicators: list[dict[str, Any]] = []
    spf_lower = spf.lower()
    dmarc_lower = dmarc.lower()
    dkim_lower = dkim.lower()

    if "fail" in spf_lower:
        auth_indicators.append({
            "type": "spf_fail",
            "severity": "high",
            "description": f"Sender Policy Framework (SPF) check failed ({spf})",
            "weight": 15,
        })
    if "fail" in dmarc_lower:
        auth_indicators.append({
            "type": "dmarc_fail",
            "severity": "high",
            "description": f"DMARC authentication failed ({dmarc})",
            "weight": 15,
        })
    if "fail" in dkim_lower:
        auth_indicators.append({
            "type": "dkim_fail",
            "severity": "medium",
            "description": f"DKIM digital signature failed ({dkim})",
            "weight": 10,
        })

    # 6. Risk Score Aggregation & Classification
    all_heuristics = (
        heuristic_text_inds
        + [i for i in url_indicators if i.get("type") != "ml_model"]
        + impers_indicators
        + auth_indicators
    )
    combined_heur_score = calculate_score(all_heuristics) / 100.0

    all_ml_probs: list[float] = []
    if ml_email_prob is not None:
        all_ml_probs.append(ml_email_prob)
    all_ml_probs.extend([p for p in ml_url_scores if p > 0.0])
    max_ml = max(all_ml_probs) if all_ml_probs else None

    blended_risk = monotonic_blend(combined_heur_score, max_ml)
    # Ensure individual critical engine verdicts are preserved
    risk_score = round(min(1.0, max(blended_risk, text_score, url_score, impers_score)), 3)

    if risk_score >= 0.7:
        classification = "phishing"
    elif risk_score >= 0.35:
        classification = "suspicious"
    else:
        classification = "safe"

    severity = get_severity(round(risk_score * 100))

    # 7. Build Signals Dictionary & Indicators Summary
    all_raw_indicators = text_indicators + url_indicators + impers_indicators + auth_indicators
    sorted_inds = sorted(all_raw_indicators, key=_indicator_weight, reverse=True)
    seen_keys: set[tuple[str, str]] = set()
    indicators_summary: list[dict[str, Any]] = []
    for ind in sorted_inds:
        k = (str(ind.get("type")), str(ind.get("description")))
        if k not in seen_keys:
            seen_keys.add(k)
            indicators_summary.append(ind)

    top_indicators = indicators_summary[:10]

    signals_dict = dict(signals)
    signals_dict.update({
        "text_model": round(ml_email_score, 4),
        "url_model": round(url_model, 4),
        "ml_url_scores": [round(s, 4) for s in ml_url_scores],
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "impersonation": round(impers_score, 4),
        "indicators_summary": indicators_summary,
    })

    # 8. Update processed_emails record with state -> 'analyzed'
    processed_email.risk_score = risk_score
    processed_email.classification = classification
    processed_email.signals = signals_dict
    processed_email.processing_status = "analyzed"
    processed_email.updated_at = datetime.now(timezone.utc)
    await db.commit()

    # 9. Create scan_results row
    explanation_text = _build_explanation(
        sender=sender,
        subject=subject,
        risk_score=risk_score,
        severity=severity,
        text_score=text_score,
        url_score=url_score,
        impers_score=impers_score,
        top_indicators=top_indicators,
    )
    engine_results = {
        "phishing": {"score": text_score, "indicators": text_indicators},
        "url": {"score": url_score, "indicators": url_indicators, "urls_analyzed": len(urls)},
        "impersonation": {"score": impers_score, "indicators": impers_indicators},
        "auth": {"spf": spf, "dkim": dkim, "dmarc": dmarc, "indicators": auth_indicators},
    }

    scan_result = ScanResult(
        id=str(uuid.uuid4()),
        owner_user_id=processed_email.owner_user_id,
        provider_message_id=processed_email.gmail_message_id,
        verdict=classification,
        risk_score=risk_score,
        scan_details={
            "severity": severity,
            "risk_score": risk_score,
            "indicators": top_indicators,
            "explanation": explanation_text,
            "engine_results": engine_results,
        },
    )
    db.add(scan_result)
    await db.flush()

    # 10. Update processed_emails.scan_result_id and 11. transition status -> 'completed'
    processed_email.scan_result_id = scan_result.id
    processed_email.processing_status = "completed"
    processed_email.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(processed_email)

    # Trigger Realtime Notification Hook (D3)
    try:
        await notify_email_processed(db, str(processed_email.id), supabase_client=supabase_client)
    except Exception as exc:
        logger.warning("Failed triggering realtime notification for %s: %s", processed_email_id, exc)

    logger.info(
        "Email analysis completed: processed_email_id=%s, risk_score=%.3f, classification=%s, scan_result_id=%s",
        processed_email_id,
        risk_score,
        classification,
        scan_result.id,
    )

    # 12. Return summary
    return {
        "processed_email_id": str(processed_email.id),
        "risk_score": risk_score,
        "classification": classification,
        "scan_result_id": str(scan_result.id),
        "status": "completed",
    }
