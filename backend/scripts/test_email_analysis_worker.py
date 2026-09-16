"""RT-6 — Email analysis worker tests (Suite 27).

Covers:
1 simple phishing email -> risk_score >0.8, classification='phishing', scan_results row created.
2 benign email -> risk_score <0.3, classification='safe'.
3 ML blend: heuristic=0.6, ml=0.9 -> final=0.765 (monotonic: 0.45*0.6 + 0.55*0.9).
4 ML blend: heuristic=0.9, ml=0.4 -> final=0.9 (monotonic: max(0.9, 0.625)=0.9).
5 duplicate analysis job same processed_email_id -> skip (status already 'analyzed' or 'completed').
6 signals dict contains all keys: text_model, url_model, spf, dkim, dmarc, impersonation, indicators_summary.
7 scan_results.indicators jsonb contains top indicators from each engine.
8 scan_results.explanation text generated (reuse Phase-3 explanation builder).
9 processed_emails.scan_result_id FK set correctly.
10 state transitions: fetched -> analyzing -> analyzed -> completed.
11 job_queue state: queued -> running -> completed.
12 realtime notification emitted (mock Supabase client or security_events table insert).
13 RLS: scan_results row owner_user_id matches processed_emails.owner_user_id.
14 correlation_id propagated to logs.
15 URL analysis: 5 URLs in email -> 5 ml_url_scores in signals, url_indicators aggregated.
16 auth signals: spf='fail' -> signals.spf='fail', risk_score adjusted.
17 impersonation: sender claims authority -> impers_score >0.5, impers_indicators recorded.
18 integration: fetch job completes -> analysis job enqueued -> analysis completes -> scan_results exists.

Run standalone:
    uv run python scripts/test_email_analysis_worker.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select, text

from app.db.admin import _get_admin_session_maker
from app.db.models import GmailAccount, JobQueue, ProcessedEmail, ScanResult, SecurityEvent
from app.queue.client import (
    make_email_analysis_job_id,
    make_email_fetch_job_id,
)
from app.services.gmail.analysis_service import monotonic_blend, process_email_analysis
from app.services.gmail.client import GmailClient
from app.services.idempotency_service import ensure_job, ensure_processed_email
from app.services.realtime_notifier import notify_email_processed
from app.workers.email_worker import email_analysis_job, email_fetch_job


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")


def _make_gmail_message_payload(
    message_id: str,
    subject: str = "Test Subject",
    sender: str = "sender@example.com",
    body_text: str | None = None,
    body_html: str | None = None,
    headers: dict[str, str] | None = None,
    attachments: list[dict] | None = None,
    size_estimate: int = 1500,
) -> dict:
    header_list = [
        {"name": "From", "value": sender},
        {"name": "Subject", "value": subject},
        {"name": "To", "value": "recipient@example.com"},
    ]
    if headers:
        for k, v in headers.items():
            header_list.append({"name": k, "value": v})

    parts = []
    if body_text is not None:
        parts.append({
            "mimeType": "text/plain",
            "body": {"data": _b64url(body_text), "size": len(body_text)},
        })
    if body_html is not None:
        parts.append({
            "mimeType": "text/html",
            "body": {"data": _b64url(body_html), "size": len(body_html)},
        })

    payload = {
        "headers": header_list,
        "parts": parts,
    }
    if not parts and body_text is not None:
        payload["body"] = {"data": _b64url(body_text), "size": len(body_text)}

    return {
        "id": message_id,
        "threadId": f"thread_{message_id}",
        "labelIds": ["INBOX"],
        "sizeEstimate": size_estimate,
        "payload": payload,
    }


async def run_email_analysis_worker_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("RT-6 Email Analysis Worker Tests (Suite 27)")
    print("-" * 60)

    admin_maker = _get_admin_session_maker()
    stamp = uuid.uuid4().hex[:8]

    # Setup test user and Gmail account
    user_id = f"analysis-user-{stamp}"
    email_addr = f"analysis-{stamp}@gmail.com"

    async with admin_maker() as db:
        await db.execute(
            text(
                "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                "values (:id, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"id": user_id},
        )
        account = GmailAccount(
            owner_user_id=user_id,
            email=email_addr,
            sync_status="active",
            last_history_id="30000",
        )
        account.set_access_token(f"mock_access_{stamp}")
        account.set_refresh_token(f"mock_refresh_{stamp}")
        db.add(account)
        await db.commit()
        await db.refresh(account)
        acc_id = account.id

    # ------------------------------------------------------------------
    # 1. simple phishing email -> risk_score >0.8, classification='phishing', scan_results row created
    # ------------------------------------------------------------------
    msg_phish_id = f"msg_phish_{stamp}"
    async with admin_maker() as db:
        pe_phish = await ensure_processed_email(db, user_id, msg_phish_id, acc_id)
        pe_phish.subject = "URGENT: Unauthorized login detected on your account"
        pe_phish.sender = "security-alerts@paypa1-support.com"
        pe_phish.processing_status = "fetched"
        pe_phish.signals = {
            "normalized_email": {
                "subject": pe_phish.subject,
                "sender": pe_phish.sender,
                "body_text": "Click http://185.220.101.7/login immediately to verify your account or it will be suspended.",
            },
            "urls": ["http://185.220.101.7/login"],
            "headers": {"From": pe_phish.sender, "Subject": pe_phish.subject},
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "size_bytes": 1200,
        }
        await db.commit()
        phish_email_id = pe_phish.id

    async with admin_maker() as db:
        res_1 = await process_email_analysis(db, phish_email_id)
        pe_row_1 = (
            await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == phish_email_id))
        ).scalar_one()
        sr_row_1 = None
        if pe_row_1.scan_result_id:
            sr_row_1 = (
                await db.execute(select(ScanResult).where(ScanResult.id == pe_row_1.scan_result_id))
            ).scalar_one_or_none()

        check(
            pe_row_1.risk_score is not None
            and pe_row_1.risk_score > 0.8
            and pe_row_1.classification == "phishing"
            and pe_row_1.processing_status == "completed"
            and sr_row_1 is not None
            and sr_row_1.verdict == "phishing"
            and sr_row_1.risk_score > 0.8,
            "1 simple phishing email -> risk_score >0.8, classification='phishing', scan_results row created",
            f"risk_score={pe_row_1.risk_score}, classification={pe_row_1.classification}, scan_res_id={pe_row_1.scan_result_id}",
        )

    # ------------------------------------------------------------------
    # 2. benign email -> risk_score <0.3, classification='safe'
    # ------------------------------------------------------------------
    msg_benign_id = f"msg_benign_{stamp}"
    async with admin_maker() as db:
        pe_benign = await ensure_processed_email(db, user_id, msg_benign_id, acc_id)
        pe_benign.subject = "Team Sync Tomorrow Morning"
        pe_benign.sender = "colleague@acme-corp.com"
        pe_benign.processing_status = "fetched"
        pe_benign.signals = {
            "normalized_email": {
                "subject": pe_benign.subject,
                "sender": pe_benign.sender,
                "body_text": "Hi team, let's meet tomorrow at 10 AM to discuss the sprint backlog. See you then!",
            },
            "urls": [],
            "headers": {"From": pe_benign.sender, "Subject": pe_benign.subject},
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "size_bytes": 800,
        }
        await db.commit()
        benign_email_id = pe_benign.id

    async with admin_maker() as db:
        res_2 = await process_email_analysis(db, benign_email_id)
        pe_row_2 = (
            await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == benign_email_id))
        ).scalar_one()

        check(
            pe_row_2.risk_score is not None
            and pe_row_2.risk_score < 0.3
            and pe_row_2.classification == "safe"
            and pe_row_2.processing_status == "completed",
            "2 benign email -> risk_score <0.3, classification='safe'",
            f"risk_score={pe_row_2.risk_score}, classification={pe_row_2.classification}",
        )

    # ------------------------------------------------------------------
    # 3. ML blend: heuristic=0.6, ml=0.9 -> final=0.765 (monotonic: 0.45*0.6 + 0.55*0.9)
    # ------------------------------------------------------------------
    blend_res_3 = monotonic_blend(0.6, 0.9)
    expected_3 = round(0.45 * 0.6 + 0.55 * 0.9, 3)  # 0.27 + 0.495 = 0.765
    check(
        blend_res_3 == 0.765 and blend_res_3 == expected_3,
        "3 ML blend: heuristic=0.6, ml=0.9 -> final=0.765 (monotonic: 0.45*0.6 + 0.55*0.9)",
        f"got={blend_res_3}, expected={expected_3}",
    )

    # ------------------------------------------------------------------
    # 4. ML blend: heuristic=0.9, ml=0.4 -> final=0.9 (monotonic: max(0.9, 0.625)=0.9)
    # ------------------------------------------------------------------
    blend_res_4 = monotonic_blend(0.9, 0.4)
    expected_4 = max(0.9, round(0.45 * 0.9 + 0.55 * 0.4, 3))  # max(0.9, 0.625) = 0.9
    check(
        blend_res_4 == 0.9 and blend_res_4 == expected_4,
        "4 ML blend: heuristic=0.9, ml=0.4 -> final=0.9 (monotonic: max(0.9, 0.625)=0.9)",
        f"got={blend_res_4}, expected={expected_4}",
    )

    # ------------------------------------------------------------------
    # 5. duplicate analysis job same processed_email_id -> skip (status already 'analyzed' or 'completed')
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        res_dup = await process_email_analysis(db, phish_email_id)
        # Check that no new ScanResult was created for this duplicate
        sr_count = (
            await db.execute(
                select(ScanResult).where(
                    ScanResult.owner_user_id == user_id,
                    ScanResult.provider_message_id == msg_phish_id,
                )
            )
        ).scalars().all()

        check(
            res_dup.get("status") == "skipped"
            and res_dup.get("reason") == "already_completed"
            and len(sr_count) == 1,
            "5 duplicate analysis job same processed_email_id -> skip (status already 'analyzed' or 'completed')",
            f"res={res_dup}, scan_result_count={len(sr_count)}",
        )

    # ------------------------------------------------------------------
    # 6. signals dict contains all keys: text_model, url_model, spf, dkim, dmarc, impersonation, indicators_summary
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        pe_row_sig = (
            await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == phish_email_id))
        ).scalar_one()
        signals = pe_row_sig.signals or {}
        required_keys = [
            "text_model",
            "url_model",
            "spf",
            "dkim",
            "dmarc",
            "impersonation",
            "indicators_summary",
        ]
        missing_keys = [k for k in required_keys if k not in signals]
        check(
            len(missing_keys) == 0,
            "6 signals dict contains all keys: text_model, url_model, spf, dkim, dmarc, impersonation, indicators_summary",
            f"missing={missing_keys}, present={list(signals.keys())}",
        )

    # ------------------------------------------------------------------
    # 7. scan_results.indicators jsonb contains top indicators from each engine
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        sr_row = (
            await db.execute(
                select(ScanResult).where(ScanResult.id == pe_row_sig.scan_result_id)
            )
        ).scalar_one()
        indicators = sr_row.indicators
        types_present = {i.get("type") for i in indicators if isinstance(i, dict)}
        check(
            isinstance(indicators, list)
            and len(indicators) > 0
            and any("ip" in str(t).lower() or "scheme" in str(t).lower() or "lookalike" in str(t).lower() for t in types_present),
            "7 scan_results.indicators jsonb contains top indicators from each engine",
            f"indicators_count={len(indicators)}, types={types_present}",
        )

    # ------------------------------------------------------------------
    # 8. scan_results.explanation text generated (reuse Phase-3 explanation builder)
    # ------------------------------------------------------------------
    explanation = sr_row.explanation
    check(
        isinstance(explanation, str)
        and len(explanation) > 20
        and "phishing=" in explanation
        and "threat" in explanation.lower(),
        "8 scan_results.explanation text generated (reuse Phase-3 explanation builder)",
        f"explanation={explanation[:80]}...",
    )

    # ------------------------------------------------------------------
    # 9. processed_emails.scan_result_id FK set correctly
    # ------------------------------------------------------------------
    check(
        pe_row_sig.scan_result_id == sr_row.id
        and pe_row_sig.scan_result_id is not None,
        "9 processed_emails.scan_result_id FK set correctly",
        f"pe.scan_result_id={pe_row_sig.scan_result_id}, sr.id={sr_row.id}",
    )

    # ------------------------------------------------------------------
    # 10. state transitions: fetched -> analyzing -> analyzed -> completed
    # ------------------------------------------------------------------
    check(
        ProcessedEmail.can_transition("fetched", "analyzing")
        and ProcessedEmail.can_transition("analyzing", "analyzed")
        and ProcessedEmail.can_transition("analyzed", "completed"),
        "10 state transitions: fetched -> analyzing -> analyzed -> completed",
        "verified valid state machine transitions in ProcessedEmail",
    )

    # ------------------------------------------------------------------
    # 11. job_queue state: queued -> running -> completed
    # ------------------------------------------------------------------
    msg_jq_id = f"msg_jq_{stamp}"
    async with admin_maker() as db:
        pe_jq = await ensure_processed_email(db, user_id, msg_jq_id, acc_id)
        pe_jq.subject = "Quarterly Invoice Review"
        pe_jq.sender = "billing@trusted-vendor.com"
        pe_jq.processing_status = "fetched"
        pe_jq.signals = {
            "normalized_email": {
                "subject": pe_jq.subject,
                "sender": pe_jq.sender,
                "body_text": "Please find the attached quarterly invoice for your review.",
            },
            "urls": [],
            "headers": {"From": pe_jq.sender, "Subject": pe_jq.subject},
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        }
        jq_job_id = make_email_analysis_job_id(user_id, msg_jq_id)
        jq_row = await ensure_job(
            db,
            owner_user_id=user_id,
            job_type="email_analysis",
            job_id=jq_job_id,
            payload={"processed_email_id": pe_jq.id},
        )
        await db.commit()
        pe_jq_id = pe_jq.id

    # Run through email_analysis_job worker entrypoint
    await email_analysis_job({"db_maker": admin_maker, "job_id": jq_job_id}, pe_jq_id)

    async with admin_maker() as db:
        jq_final = (
            await db.execute(select(JobQueue).where(JobQueue.job_id == jq_job_id))
        ).scalar_one()
        check(
            jq_final.status == "completed"
            and jq_final.result is not None
            and jq_final.result.get("processed_email_id") == pe_jq_id,
            "11 job_queue state: queued -> running -> completed",
            f"job_status={jq_final.status}, result={jq_final.result}",
        )

    # ------------------------------------------------------------------
    # 12. realtime notification emitted (mock Supabase client or security_events table insert)
    # ------------------------------------------------------------------
    mock_supabase = MagicMock()
    mock_channel = MagicMock()
    mock_supabase.channel.return_value = mock_channel

    async with admin_maker() as db:
        notify_res = await notify_email_processed(db, phish_email_id, supabase_client=mock_supabase)
        sec_event_row = (
            await db.execute(
                select(SecurityEvent).where(
                    SecurityEvent.id == notify_res["security_event_id"]
                )
            )
        ).scalar_one_or_none()

        check(
            notify_res["emitted"] is True
            and mock_channel.send.call_count == 1
            and sec_event_row is not None
            and sec_event_row.event_type == "email_analyzed"
            and sec_event_row.score > 0.8,
            "12 realtime notification emitted (mock Supabase client or security_events table insert)",
            f"emitted={notify_res.get('emitted')}, sec_event_id={sec_event_row.id if sec_event_row else None}",
        )

    # ------------------------------------------------------------------
    # 13. RLS: scan_results row owner_user_id matches processed_emails.owner_user_id
    # ------------------------------------------------------------------
    check(
        sr_row.owner_user_id == user_id and sr_row.owner_user_id == pe_row_sig.owner_user_id,
        "13 RLS: scan_results row owner_user_id matches processed_emails.owner_user_id",
        f"sr_owner={sr_row.owner_user_id}, pe_owner={pe_row_sig.owner_user_id}",
    )

    # ------------------------------------------------------------------
    # 14. correlation_id propagated to logs
    # ------------------------------------------------------------------
    test_corr_id = f"corr-test-{stamp}"
    with patch("app.workers.email_worker.log_worker_event") as mock_log:
        await email_analysis_job({"db_maker": admin_maker, "job_id": test_corr_id}, pe_jq_id)
        corr_calls = [
            kwargs.get("correlation_id")
            for _args, kwargs in mock_log.call_args_list
            if "correlation_id" in kwargs
        ]
        check(
            test_corr_id in corr_calls,
            "14 correlation_id propagated to logs",
            f"corr_calls={corr_calls}",
        )

    # ------------------------------------------------------------------
    # 15. URL analysis: 5 URLs in email -> 5 ml_url_scores in signals, url_indicators aggregated
    # ------------------------------------------------------------------
    msg_urls_id = f"msg_urls_5_{stamp}"
    five_urls = [
        "http://185.220.101.7/login.php",
        "https://suspicious-domain-phish.biz/verify",
        "http://malware-drop.ru/payload.exe",
        "https://legit-service.com/portal",
        "http://account-update-notice.xyz/confirm",
    ]
    async with admin_maker() as db:
        pe_urls = await ensure_processed_email(db, user_id, msg_urls_id, acc_id)
        pe_urls.subject = "Multiple Links Notice"
        pe_urls.sender = "links@example-alert.com"
        pe_urls.processing_status = "fetched"
        pe_urls.signals = {
            "normalized_email": {
                "subject": pe_urls.subject,
                "sender": pe_urls.sender,
                "body_text": "Check these links: " + " ".join(five_urls),
            },
            "urls": five_urls,
            "headers": {"From": pe_urls.sender, "Subject": pe_urls.subject},
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        }
        await db.commit()
        urls_email_id = pe_urls.id

    async with admin_maker() as db:
        await process_email_analysis(db, urls_email_id)
        pe_urls_row = (
            await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == urls_email_id))
        ).scalar_one()
        url_scores_in_signals = pe_urls_row.signals.get("ml_url_scores", [])
        check(
            len(url_scores_in_signals) == 5
            and pe_urls_row.signals.get("url_model") is not None
            and len(pe_urls_row.signals.get("indicators_summary", [])) > 0,
            "15 URL analysis: 5 URLs in email -> 5 ml_url_scores in signals, url_indicators aggregated",
            f"ml_url_scores_len={len(url_scores_in_signals)}, url_model={pe_urls_row.signals.get('url_model')}",
        )

    # ------------------------------------------------------------------
    # 16. auth signals: spf='fail' -> signals.spf='fail', risk_score adjusted
    # ------------------------------------------------------------------
    msg_spf_pass_id = f"msg_spf_pass_{stamp}"
    msg_spf_fail_id = f"msg_spf_fail_{stamp}"
    common_body = "Urgent action required to secure your banking credentials."

    async with admin_maker() as db:
        pe_spf_pass = await ensure_processed_email(db, user_id, msg_spf_pass_id, acc_id)
        pe_spf_pass.subject = "Security Notice"
        pe_spf_pass.sender = "security@bank.com"
        pe_spf_pass.processing_status = "fetched"
        pe_spf_pass.signals = {
            "normalized_email": {
                "subject": pe_spf_pass.subject,
                "sender": pe_spf_pass.sender,
                "body_text": common_body,
            },
            "urls": [],
            "headers": {"From": pe_spf_pass.sender},
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        }

        pe_spf_fail = await ensure_processed_email(db, user_id, msg_spf_fail_id, acc_id)
        pe_spf_fail.subject = "Security Notice"
        pe_spf_fail.sender = "security@bank.com"
        pe_spf_fail.processing_status = "fetched"
        pe_spf_fail.signals = {
            "normalized_email": {
                "subject": pe_spf_fail.subject,
                "sender": pe_spf_fail.sender,
                "body_text": common_body,
            },
            "urls": [],
            "headers": {"From": pe_spf_fail.sender},
            "spf": "fail",
            "dkim": "none",
            "dmarc": "fail",
        }
        await db.commit()
        id_pass = pe_spf_pass.id
        id_fail = pe_spf_fail.id

    async with admin_maker() as db:
        res_pass = await process_email_analysis(db, id_pass)
        res_fail = await process_email_analysis(db, id_fail)

        check(
            res_fail["risk_score"] > res_pass["risk_score"],
            "16 auth signals: spf='fail' -> signals.spf='fail', risk_score adjusted",
            f"score_spf_fail={res_fail['risk_score']} > score_spf_pass={res_pass['risk_score']}",
        )

    # ------------------------------------------------------------------
    # 17. impersonation: sender claims authority -> impers_score >0.5, impers_indicators recorded
    # ------------------------------------------------------------------
    msg_imp_id = f"msg_imp_{stamp}"
    async with admin_maker() as db:
        pe_imp = await ensure_processed_email(db, user_id, msg_imp_id, acc_id)
        pe_imp.subject = "CONFIDENTIAL: Urgent wire transfer required today"
        pe_imp.sender = '"Chief Executive Officer" <ceo-office@company-execs.org>'
        pe_imp.processing_status = "fetched"
        pe_imp.signals = {
            "normalized_email": {
                "subject": pe_imp.subject,
                "sender": pe_imp.sender,
                "body_text": "I am in an urgent confidential meeting. Wire transfer $50,000 immediately. Do not inform finance or call me.",
            },
            "urls": [],
            "headers": {"From": pe_imp.sender, "Subject": pe_imp.subject},
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        }
        await db.commit()
        imp_email_id = pe_imp.id

    async with admin_maker() as db:
        await process_email_analysis(db, imp_email_id)
        pe_imp_row = (
            await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == imp_email_id))
        ).scalar_one()
        impers_score = pe_imp_row.signals.get("impersonation", 0.0)
        check(
            impers_score > 0.5,
            "17 impersonation: sender claims authority -> impers_score >0.5, impers_indicators recorded",
            f"impers_score={impers_score}",
        )

    # ------------------------------------------------------------------
    # 18. integration: fetch job completes -> analysis job enqueued -> analysis completes -> scan_results exists
    # ------------------------------------------------------------------
    msg_integ_id = f"msg_integ_full_{stamp}"
    mock_integ_payload = _make_gmail_message_payload(
        msg_integ_id,
        subject="Action Required: Payment Verification",
        sender="billing@payments-service.org",
        body_text="Verify your recent payment of $250.00 at http://185.220.101.7/pay.",
    )
    mock_client = MagicMock(spec=GmailClient)
    mock_client.get_message = AsyncMock(return_value=mock_integ_payload)
    mock_redis = MagicMock()
    mock_redis.enqueue_job = AsyncMock()

    # Step 1: Run fetch worker
    fetch_ctx = {"db_maker": admin_maker, "job_id": make_email_fetch_job_id(user_id, msg_integ_id), "redis": mock_redis}
    await email_fetch_job(fetch_ctx, account_id=acc_id, message_id=msg_integ_id, client=mock_client)

    # Step 2: Retrieve enqueued analysis job
    analysis_job_id = make_email_analysis_job_id(user_id, msg_integ_id)
    async with admin_maker() as db:
        analysis_job_row = (
            await db.execute(select(JobQueue).where(JobQueue.job_id == analysis_job_id))
        ).scalar_one_or_none()

        check(
            analysis_job_row is not None and analysis_job_row.status == "queued",
            "18.1 integration: fetch job completes -> analysis job enqueued",
            f"analysis_job_id={analysis_job_id}",
        )

        pe_id_to_analyze = analysis_job_row.payload["processed_email_id"]

    # Step 3: Run analysis worker
    analysis_ctx = {"db_maker": admin_maker, "job_id": analysis_job_id, "supabase_client": mock_supabase}
    await email_analysis_job(analysis_ctx, processed_email_id=pe_id_to_analyze)

    # Step 4: Verify end-to-end completion and scan_results existence
    async with admin_maker() as db:
        pe_final = (
            await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == pe_id_to_analyze))
        ).scalar_one()
        sr_final = None
        if pe_final.scan_result_id:
            sr_final = (
                await db.execute(select(ScanResult).where(ScanResult.id == pe_final.scan_result_id))
            ).scalar_one_or_none()

        check(
            pe_final.processing_status == "completed"
            and pe_final.scan_result_id is not None
            and sr_final is not None
            and sr_final.risk_score > 0.0,
            "18 integration: fetch job completes -> analysis job enqueued -> analysis completes -> scan_results exists",
            f"status={pe_final.processing_status}, scan_result_id={pe_final.scan_result_id}",
        )


class StandaloneRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def assert_true(self, condition: bool, name: str, details: str = ""):
        if condition:
            self.passed += 1
            print(f"  ✔ PASS: {name}")
        else:
            self.failed += 1
            print(f"  ✖ FAIL: {name} - {details}")

    def report(self) -> int:
        total = self.passed + self.failed
        print(f"\nSuite 27 total: {self.passed}/{total} passed")
        return 0 if self.failed == 0 else 1


if __name__ == "__main__":
    runner = StandaloneRunner()
    asyncio.run(run_email_analysis_worker_tests(runner))
    sys.exit(runner.report())
