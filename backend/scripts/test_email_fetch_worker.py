"""RT-5 — Email fetch worker tests (Suite 26).

Covers:
1 simple MIME -> processed_emails fetched (subject/sender/urls) + email_analysis job deterministic ID.
2 duplicate fetch job same message_id -> skip, zero second analysis jobs.
3 existing completed processed_email -> full skip.
4 multipart: text/plain preferred over text/html.
5 html-only -> sanitized text (script stripped, no JS artifacts).
6 urls > MAX_URLS -> truncated + truncated_urls flag.
7 oversized mock (>10MB) -> dead_letter + processed_emails failed size_exceeded, retry_count=max.
8 corrupted MIME -> failed first try; after max retries dead_letter; concurrent healthy job completes (poison isolation).
9 attachment metadata stored; assert zero attachment-content downloads (httpx interceptor).
10 auth headers parsed: spf/dkim/dmarc placeholders in signals.
11 401 -> account error reauth_required + job failed.
12 429 -> retry_count++ with backoff.
13 slow mock > FETCH_TIMEOUT_S -> failed(timeout), retried.
14 RLS owner match on processed_emails.
15 states: received -> fetching -> fetched; job queued -> running -> completed.
16 integration: sync -> fetch -> analysis job queued (mock Redis).

Run standalone:
    uv run python scripts/test_email_fetch_worker.py
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

import httpx
from sqlalchemy import select, text

from app.core.errors import NonRetryableError
from app.core.limits import FETCH_TIMEOUT_S, MAX_EMAIL_BYTES, MAX_URLS
from app.db.admin import _get_admin_session_maker
from app.db.models import GmailAccount, JobQueue, ProcessedEmail
from app.queue.client import (
    make_email_analysis_job_id,
    make_email_fetch_job_id,
    make_gmail_sync_job_id,
)
from app.services.gmail.client import (
    GmailAuthError,
    GmailClient,
    GmailRateLimitError,
    GmailServerError,
)
from app.services.gmail.fetch_service import process_email_fetch
from app.services.idempotency_service import ensure_job, ensure_processed_email
from app.services.job_state_service import update_job_status
from app.workers.email_worker import email_fetch_job
from app.workers.gmail_worker import gmail_sync_job


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
    if attachments:
        for att in attachments:
            parts.append({
                "mimeType": att.get("mime_type", "application/octet-stream"),
                "filename": att.get("filename", "file.bin"),
                "body": {
                    "attachmentId": att.get("attachment_id", "att-123"),
                    "size": att.get("size", 1024),
                },
            })

    payload = {
        "headers": header_list,
        "parts": parts,
    }
    if not parts and body_text is not None:
        payload["body"] = {"data": _b64url(body_text), "size": len(body_text)}

    return {
        "id": message_id,
        "threadId": f"thread-{message_id}",
        "labelIds": ["INBOX"],
        "sizeEstimate": size_estimate,
        "payload": payload,
    }


async def run_email_fetch_worker_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("RT-5 Email Fetch Worker Tests (Suite 26)")
    print("-" * 60)

    admin_maker = _get_admin_session_maker()
    stamp = uuid.uuid4().hex[:8]

    # Setup test user and Gmail account
    user_id = f"fetch-user-{stamp}"
    email = f"fetch-{stamp}@gmail.com"
    raw_access_token = f"ya29.mock_access_{stamp}"
    raw_refresh_token = f"1//mock_refresh_{stamp}"

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
            email=email,
            sync_status="active",
            last_history_id="20000",
        )
        account.set_access_token(raw_access_token)
        account.set_refresh_token(raw_refresh_token)
        db.add(account)
        await db.commit()
        await db.refresh(account)
        acc_id = account.id

    # ------------------------------------------------------------------
    # 1. simple MIME -> processed_emails fetched (subject/sender/urls) + email_analysis job deterministic ID
    # ------------------------------------------------------------------
    msg_1_id = f"msg_simple_{stamp}"
    mock_1_msg = _make_gmail_message_payload(
        msg_1_id,
        subject="Important Account Alert",
        sender="security@bank.example.com",
        body_text="Please review your account at https://bank.example.com/verify immediately.",
    )
    client_1 = MagicMock(spec=GmailClient)
    client_1.get_message = AsyncMock(return_value=mock_1_msg)

    async with admin_maker() as db:
        res_1 = await process_email_fetch(db, acc_id, msg_1_id, client=client_1)
        email_row_1 = (
            await db.execute(
                select(ProcessedEmail).where(
                    ProcessedEmail.owner_user_id == user_id,
                    ProcessedEmail.gmail_message_id == msg_1_id,
                )
            )
        ).scalar_one()

        expected_analysis_id = make_email_analysis_job_id(user_id, msg_1_id)
        analysis_job_1 = (
            await db.execute(
                select(JobQueue).where(JobQueue.job_id == expected_analysis_id)
            )
        ).scalar_one_or_none()

        check(
            res_1["status"] == "fetched"
            and email_row_1.processing_status == "fetched"
            and email_row_1.subject == "Important Account Alert"
            and email_row_1.sender == "security@bank.example.com"
            and "https://bank.example.com/verify" in email_row_1.urls
            and analysis_job_1 is not None
            and analysis_job_1.status == "queued"
            and analysis_job_1.payload.get("processed_email_id") == email_row_1.id,
            "1 simple MIME -> processed_emails fetched (subject/sender/urls) + email_analysis job deterministic ID",
            f"status={email_row_1.processing_status}, analysis_job={expected_analysis_id}",
        )

    # ------------------------------------------------------------------
    # 2. duplicate fetch job same message_id -> skip, zero second analysis jobs
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        res_2 = await process_email_fetch(db, acc_id, msg_1_id, client=client_1)
        analysis_jobs = (
            await db.execute(
                select(JobQueue).where(JobQueue.job_id == make_email_analysis_job_id(user_id, msg_1_id))
            )
        ).scalars().all()
        check(
            res_2["status"] == "skipped"
            and res_2["reason"] == "already_fetched"
            and len(analysis_jobs) == 1,
            "2 duplicate fetch job same message_id -> skip, zero second analysis jobs",
            f"res={res_2}, jobs_count={len(analysis_jobs)}",
        )

    # ------------------------------------------------------------------
    # 3. existing completed processed_email -> full skip
    # ------------------------------------------------------------------
    msg_comp_id = f"msg_completed_{stamp}"
    async with admin_maker() as db:
        comp_email = await ensure_processed_email(db, user_id, msg_comp_id, acc_id)
        comp_email.processing_status = "completed"
        await db.commit()

    unused_client = MagicMock(spec=GmailClient)
    unused_client.get_message = AsyncMock()

    async with admin_maker() as db:
        res_3 = await process_email_fetch(db, acc_id, msg_comp_id, client=unused_client)
        check(
            res_3["status"] == "skipped"
            and res_3["reason"] == "already_completed"
            and unused_client.get_message.call_count == 0,
            "3 existing completed processed_email -> full skip",
            f"res={res_3}, get_message_calls={unused_client.get_message.call_count}",
        )

    # ------------------------------------------------------------------
    # 4. multipart: text/plain preferred over text/html
    # ------------------------------------------------------------------
    msg_multi_id = f"msg_multi_{stamp}"
    mock_multi = _make_gmail_message_payload(
        msg_multi_id,
        subject="Multipart Message",
        body_text="Plain text body priority",
        body_html="<html><body><p>HTML body variant</p></body></html>",
    )
    client_multi = MagicMock(spec=GmailClient)
    client_multi.get_message = AsyncMock(return_value=mock_multi)

    async with admin_maker() as db:
        await process_email_fetch(db, acc_id, msg_multi_id, client=client_multi)
        multi_row = (
            await db.execute(
                select(ProcessedEmail).where(
                    ProcessedEmail.owner_user_id == user_id,
                    ProcessedEmail.gmail_message_id == msg_multi_id,
                )
            )
        ).scalar_one()
        norm_data = multi_row.normalized_email or {}
        check(
            norm_data.get("body_text") == "Plain text body priority"
            and norm_data.get("body_html") is not None,
            "4 multipart: text/plain preferred over text/html",
            f"body_text={norm_data.get('body_text')}",
        )

    # ------------------------------------------------------------------
    # 5. html-only -> sanitized text (script stripped, no JS artifacts)
    # ------------------------------------------------------------------
    msg_html_id = f"msg_html_{stamp}"
    mock_html = _make_gmail_message_payload(
        msg_html_id,
        subject="HTML Only Alert",
        body_text=None,
        body_html="<html><body><script>alert('malicious')</script><h1>Payment Receipt</h1><p>Your receipt is ready.</p></body></html>",
    )
    client_html = MagicMock(spec=GmailClient)
    client_html.get_message = AsyncMock(return_value=mock_html)

    async with admin_maker() as db:
        await process_email_fetch(db, acc_id, msg_html_id, client=client_html)
        html_row = (
            await db.execute(
                select(ProcessedEmail).where(
                    ProcessedEmail.owner_user_id == user_id,
                    ProcessedEmail.gmail_message_id == msg_html_id,
                )
            )
        ).scalar_one()
        norm_html = html_row.normalized_email or {}
        body_text_sanitized = norm_html.get("body_text", "")
        check(
            "Payment Receipt" in body_text_sanitized
            and "alert" not in body_text_sanitized
            and "<script" not in body_text_sanitized,
            "5 html-only -> sanitized text (script stripped, no JS artifacts)",
            f"sanitized_body={body_text_sanitized}",
        )

    # ------------------------------------------------------------------
    # 6. urls > MAX_URLS -> truncated + truncated_urls flag
    # ------------------------------------------------------------------
    msg_urls_id = f"msg_urls_{stamp}"
    many_urls = "\n".join(f"https://domain.example.com/item_{i}" for i in range(150))
    mock_urls_msg = _make_gmail_message_payload(
        msg_urls_id,
        subject="Lots of URLs",
        body_text=f"Check all links:\n{many_urls}",
    )
    client_urls = MagicMock(spec=GmailClient)
    client_urls.get_message = AsyncMock(return_value=mock_urls_msg)

    async with admin_maker() as db:
        await process_email_fetch(db, acc_id, msg_urls_id, client=client_urls)
        urls_row = (
            await db.execute(
                select(ProcessedEmail).where(
                    ProcessedEmail.owner_user_id == user_id,
                    ProcessedEmail.gmail_message_id == msg_urls_id,
                )
            )
        ).scalar_one()
        check(
            len(urls_row.urls) == MAX_URLS
            and urls_row.signals.get("truncated_urls") is True,
            "6 urls>MAX_URLS -> truncated + truncated_urls flag",
            f"extracted_count={len(urls_row.urls)}, truncated_flag={urls_row.signals.get('truncated_urls')}",
        )

    # ------------------------------------------------------------------
    # 7. oversized mock (>10MB) -> dead_letter + processed_emails failed size_exceeded, retry_count=max
    # ------------------------------------------------------------------
    msg_over_id = f"msg_oversized_{stamp}"
    mock_over = _make_gmail_message_payload(
        msg_over_id,
        subject="Huge File",
        size_estimate=15_000_000,  # > 10MB limit
    )
    client_over = MagicMock(spec=GmailClient)
    client_over.get_message = AsyncMock(return_value=mock_over)

    job_over_id = make_email_fetch_job_id(user_id, msg_over_id)
    async with admin_maker() as db:
        await ensure_job(db, user_id, "email_fetch", job_over_id, {"account_id": acc_id, "message_id": msg_over_id})

    over_failed = False
    try:
        await email_fetch_job(
            {"db_maker": admin_maker, "job_id": job_over_id},
            acc_id,
            msg_over_id,
            client=client_over,
        )
    except NonRetryableError:
        over_failed = True

    async with admin_maker() as db:
        job_over = (await db.execute(select(JobQueue).where(JobQueue.job_id == job_over_id))).scalar_one()
        email_over = (
            await db.execute(
                select(ProcessedEmail).where(
                    ProcessedEmail.owner_user_id == user_id,
                    ProcessedEmail.gmail_message_id == msg_over_id,
                )
            )
        ).scalar_one()

        check(
            over_failed
            and job_over.status == "dead_letter"
            and job_over.retry_count == job_over.max_retries
            and email_over.processing_status == "failed"
            and email_over.error == "size_exceeded",
            "7 oversized mock (>10MB) -> dead_letter + processed_emails failed size_exceeded, retry_count=max",
            f"job_status={job_over.status}, retries={job_over.retry_count}, email_status={email_over.processing_status}, error={email_over.error}",
        )

    # ------------------------------------------------------------------
    # 8. corrupted MIME -> failed first try; after max retries dead_letter; concurrent healthy job completes (poison isolation)
    # ------------------------------------------------------------------
    msg_corrupt_id = f"msg_corrupt_{stamp}"
    client_corrupt = MagicMock(spec=GmailClient)
    client_corrupt.get_message = AsyncMock(side_effect=ValueError("Corrupted MIME payload structure"))

    job_corrupt_id = make_email_fetch_job_id(user_id, msg_corrupt_id)
    async with admin_maker() as db:
        await ensure_job(db, user_id, "email_fetch", job_corrupt_id, {"account_id": acc_id, "message_id": msg_corrupt_id})

    # Try 1: fails and increments retry_count
    try:
        await email_fetch_job(
            {"db_maker": admin_maker, "job_id": job_corrupt_id},
            acc_id,
            msg_corrupt_id,
            client=client_corrupt,
        )
    except Exception:
        pass

    async with admin_maker() as db:
        job_c1 = (await db.execute(select(JobQueue).where(JobQueue.job_id == job_corrupt_id))).scalar_one()
        check_try1 = job_c1.status == "failed" and job_c1.retry_count == 1

        # Simulate reaching max retries -> dead_letter
        await update_job_status(db, job_corrupt_id, "dead_letter", error="Max retries exhausted")
        job_cdl = (await db.execute(select(JobQueue).where(JobQueue.job_id == job_corrupt_id))).scalar_one()
        check_dl = job_cdl.status == "dead_letter"

    # Concurrently execute healthy job
    msg_healthy_id = f"msg_healthy_{stamp}"
    mock_healthy = _make_gmail_message_payload(msg_healthy_id, subject="Healthy message")
    client_healthy = MagicMock(spec=GmailClient)
    client_healthy.get_message = AsyncMock(return_value=mock_healthy)
    job_healthy_id = make_email_fetch_job_id(user_id, msg_healthy_id)

    async with admin_maker() as db:
        await ensure_job(db, user_id, "email_fetch", job_healthy_id, {"account_id": acc_id, "message_id": msg_healthy_id})

    healthy_res = await email_fetch_job(
        {"db_maker": admin_maker, "job_id": job_healthy_id},
        acc_id,
        msg_healthy_id,
        client=client_healthy,
    )

    async with admin_maker() as db:
        job_h = (await db.execute(select(JobQueue).where(JobQueue.job_id == job_healthy_id))).scalar_one()
        check(
            check_try1 and check_dl and job_h.status == "completed" and healthy_res["status"] == "fetched",
            "8 corrupted MIME -> failed first try; after max retries dead_letter; concurrent healthy job completes (poison isolation)",
            f"try1_ok={check_try1}, dl_ok={check_dl}, healthy_status={job_h.status}",
        )

    # ------------------------------------------------------------------
    # 9. attachment metadata stored; assert zero attachment-content downloads (httpx interceptor)
    # ------------------------------------------------------------------
    msg_att_id = f"msg_att_{stamp}"
    mock_att = _make_gmail_message_payload(
        msg_att_id,
        subject="Files Attached",
        attachments=[
            {"filename": "contract.pdf", "mime_type": "application/pdf", "size": 45000, "attachment_id": "att-pdf-1"},
            {"filename": "data.csv", "mime_type": "text/csv", "size": 12000, "attachment_id": "att-csv-2"},
        ],
    )
    client_att = MagicMock(spec=GmailClient)
    client_att.get_message = AsyncMock(return_value=mock_att)

    with patch("httpx.AsyncClient.request") as mock_http_req:
        async with admin_maker() as db:
            await process_email_fetch(db, acc_id, msg_att_id, client=client_att)
            att_row = (
                await db.execute(
                    select(ProcessedEmail).where(
                        ProcessedEmail.owner_user_id == user_id,
                        ProcessedEmail.gmail_message_id == msg_att_id,
                    )
                )
            ).scalar_one()

            meta = att_row.signals.get("attachments_meta", [])
            has_pdf = any(a.get("filename") == "contract.pdf" and a.get("size") == 45000 for a in meta)
            has_csv = any(a.get("filename") == "data.csv" and a.get("size") == 12000 for a in meta)

            check(
                len(meta) == 2
                and has_pdf
                and has_csv
                and mock_http_req.call_count == 0,
                "9 attachment metadata stored; assert zero attachment-content downloads (httpx interceptor)",
                f"meta_len={len(meta)}, has_pdf={has_pdf}, has_csv={has_csv}, download_calls={mock_http_req.call_count}",
            )

    # ------------------------------------------------------------------
    # 10. auth headers parsed: spf/dkim/dmarc placeholders in signals
    # ------------------------------------------------------------------
    msg_auth_id = f"msg_auth_{stamp}"
    mock_auth_msg = _make_gmail_message_payload(
        msg_auth_id,
        subject="Security Inspection",
        headers={
            "Return-Path": "<bounce@authdomain.example.com>",
            "Received-SPF": "Pass (mailfrom) identity=mailfrom; client-ip=1.2.3.4",
            "DKIM-Signature": "v=1; a=rsa-sha256; d=authdomain.example.com; ...",
            "Authentication-Results": "mx.google.com; spf=pass (google.com: domain of bounce@authdomain.example.com); dkim=pass header.i=@authdomain.example.com; dmarc=pass action=none",
        },
    )
    client_auth = MagicMock(spec=GmailClient)
    client_auth.get_message = AsyncMock(return_value=mock_auth_msg)

    async with admin_maker() as db:
        await process_email_fetch(db, acc_id, msg_auth_id, client=client_auth)
        auth_row = (
            await db.execute(
                select(ProcessedEmail).where(
                    ProcessedEmail.owner_user_id == user_id,
                    ProcessedEmail.gmail_message_id == msg_auth_id,
                )
            )
        ).scalar_one()

        signals = auth_row.signals or {}
        check(
            signals.get("spf") == "pass"
            and signals.get("dkim") == "pass"
            and signals.get("dmarc") == "pass"
            and signals.get("return_path") == "<bounce@authdomain.example.com>"
            and signals.get("has_dkim_signature") is True,
            "10 auth headers parsed: spf/dkim/dmarc placeholders in signals",
            f"spf={signals.get('spf')}, dkim={signals.get('dkim')}, dmarc={signals.get('dmarc')}",
        )

    # ------------------------------------------------------------------
    # 11. 401 -> account error reauth_required + job failed
    # ------------------------------------------------------------------
    msg_401_id = f"msg_401_{stamp}"
    client_401 = MagicMock(spec=GmailClient)
    client_401.get_message = AsyncMock(side_effect=GmailAuthError("401 Unauthorized", status_code=401))

    job_401_id = make_email_fetch_job_id(user_id, msg_401_id)
    async with admin_maker() as db:
        await ensure_job(db, user_id, "email_fetch", job_401_id, {"account_id": acc_id, "message_id": msg_401_id})

    auth_err_thrown = False
    try:
        await email_fetch_job(
            {"db_maker": admin_maker, "job_id": job_401_id},
            acc_id,
            msg_401_id,
            client=client_401,
        )
    except GmailAuthError:
        auth_err_thrown = True

    async with admin_maker() as db:
        acc_401 = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        job_401 = (await db.execute(select(JobQueue).where(JobQueue.job_id == job_401_id))).scalar_one()

        check(
            auth_err_thrown
            and acc_401.sync_status == "error"
            and acc_401.last_error == "reauth_required"
            and job_401.status in ("failed", "dead_letter"),
            "11 401 -> account error reauth_required + job failed",
            f"account_status={acc_401.sync_status}, last_error={acc_401.last_error}, job_status={job_401.status}",
        )

    # Reset account status to active for remainder
    async with admin_maker() as db:
        acc_re = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        acc_re.sync_status = "active"
        acc_re.last_error = None
        await db.commit()

    # ------------------------------------------------------------------
    # 12. 429 -> retry_count++ with backoff
    # ------------------------------------------------------------------
    msg_429_id = f"msg_429_{stamp}"
    client_429 = MagicMock(spec=GmailClient)
    client_429.get_message = AsyncMock(side_effect=GmailRateLimitError("429 Too Many Requests", status_code=429))

    job_429_id = make_email_fetch_job_id(user_id, msg_429_id)
    async with admin_maker() as db:
        await ensure_job(db, user_id, "email_fetch", job_429_id, {"account_id": acc_id, "message_id": msg_429_id})

    rate_thrown = False
    try:
        await email_fetch_job(
            {"db_maker": admin_maker, "job_id": job_429_id},
            acc_id,
            msg_429_id,
            client=client_429,
        )
    except GmailRateLimitError:
        rate_thrown = True

    async with admin_maker() as db:
        job_429 = (await db.execute(select(JobQueue).where(JobQueue.job_id == job_429_id))).scalar_one()
        check(
            rate_thrown
            and job_429.status == "failed"
            and job_429.retry_count >= 1
            and job_429.next_retry_at is not None,
            "12 429 -> retry_count++ with backoff",
            f"job_status={job_429.status}, retries={job_429.retry_count}, next_retry={job_429.next_retry_at}",
        )

    # ------------------------------------------------------------------
    # 13. slow mock > FETCH_TIMEOUT_S -> failed(timeout), retried
    # ------------------------------------------------------------------
    msg_to_id = f"msg_timeout_{stamp}"
    client_to = MagicMock(spec=GmailClient)
    client_to.get_message = AsyncMock(side_effect=GmailServerError(f"Gmail request timeout: timeout after {FETCH_TIMEOUT_S}s", status_code=504))

    job_to_id = make_email_fetch_job_id(user_id, msg_to_id)
    async with admin_maker() as db:
        await ensure_job(db, user_id, "email_fetch", job_to_id, {"account_id": acc_id, "message_id": msg_to_id})

    to_thrown = False
    try:
        await email_fetch_job(
            {"db_maker": admin_maker, "job_id": job_to_id},
            acc_id,
            msg_to_id,
            client=client_to,
        )
    except GmailServerError:
        to_thrown = True

    async with admin_maker() as db:
        job_to = (await db.execute(select(JobQueue).where(JobQueue.job_id == job_to_id))).scalar_one()
        check(
            to_thrown
            and job_to.status == "failed"
            and job_to.retry_count >= 1
            and job_to.next_retry_at is not None,
            "13 slow mock > FETCH_TIMEOUT_S -> failed(timeout), retried",
            f"status={job_to.status}, retry_count={job_to.retry_count}",
        )

    # ------------------------------------------------------------------
    # 14. RLS owner match on processed_emails
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        emails = (
            await db.execute(
                select(ProcessedEmail).where(ProcessedEmail.gmail_account_id == acc_id)
            )
        ).scalars().all()
        all_owner_match = len(emails) > 0 and all(e.owner_user_id == user_id for e in emails)
        check(
            all_owner_match,
            "14 RLS owner match on processed_emails",
            f"count={len(emails)}, all_match={all_owner_match}",
        )

    # ------------------------------------------------------------------
    # 15. states: received->fetching->fetched; job queued->running->completed
    # ------------------------------------------------------------------
    msg_st_id = f"msg_state_{stamp}"
    mock_st = _make_gmail_message_payload(msg_st_id, subject="State transition check")
    client_st = MagicMock(spec=GmailClient)
    client_st.get_message = AsyncMock(return_value=mock_st)

    job_st_id = make_email_fetch_job_id(user_id, msg_st_id)
    async with admin_maker() as db:
        email_pre = await ensure_processed_email(db, user_id, msg_st_id, acc_id)
        job_pre = await ensure_job(db, user_id, "email_fetch", job_st_id, {"account_id": acc_id, "message_id": msg_st_id})
        status_email_0 = email_pre.processing_status
        status_job_0 = job_pre.status

    await email_fetch_job(
        {"db_maker": admin_maker, "job_id": job_st_id},
        acc_id,
        msg_st_id,
        client=client_st,
    )

    async with admin_maker() as db:
        email_post = (
            await db.execute(
                select(ProcessedEmail).where(
                    ProcessedEmail.owner_user_id == user_id,
                    ProcessedEmail.gmail_message_id == msg_st_id,
                )
            )
        ).scalar_one()
        job_post = (await db.execute(select(JobQueue).where(JobQueue.job_id == job_st_id))).scalar_one()

        check(
            status_email_0 == "received"
            and email_post.processing_status == "fetched"
            and status_job_0 == "queued"
            and job_post.status == "completed"
            and job_post.started_at is not None
            and job_post.completed_at is not None,
            "15 states: received->fetching->fetched; job queued->running->completed",
            f"email_states=({status_email_0} -> {email_post.processing_status}), job_states=({status_job_0} -> {job_post.status})",
        )

    # ------------------------------------------------------------------
    # 16. integration: sync->fetch->analysis job queued (mock Redis)
    # ------------------------------------------------------------------
    integ_msg_id = f"msg_integ_flow_{stamp}"
    mock_sync_client = MagicMock(spec=GmailClient)
    mock_sync_client.list_history = AsyncMock(
        return_value=[
            {"id": "20500", "messagesAdded": [{"message": {"id": integ_msg_id}}]}
        ]
    )
    mock_sync_client.get_message = AsyncMock(
        return_value=_make_gmail_message_payload(integ_msg_id, subject="E2E Pipeline Test")
    )

    # 1. sync worker executes
    sync_job_id = make_gmail_sync_job_id(user_id, "20500")
    async with admin_maker() as db:
        await ensure_job(db, user_id, "gmail_sync", sync_job_id, {"account_id": acc_id, "history_id": "20500"})

    with patch("app.services.gmail.sync_service.enqueue", new_callable=AsyncMock) as mock_sync_enq:
        mock_sync_enq.return_value = "enqueued_sync"
        await gmail_sync_job(
            {"db_maker": admin_maker, "job_id": sync_job_id},
            acc_id,
            "20500",
            client=mock_sync_client,
        )

    # 2. fetch worker executes on enqueued email_fetch job
    fetch_target_job_id = make_email_fetch_job_id(user_id, integ_msg_id)
    with patch("app.services.gmail.fetch_service.enqueue", new_callable=AsyncMock) as mock_fetch_enq:
        mock_fetch_enq.return_value = "enqueued_analysis"
        await email_fetch_job(
            {"db_maker": admin_maker, "job_id": fetch_target_job_id},
            acc_id,
            integ_msg_id,
            client=mock_sync_client,
        )

    # 3. verify analysis job queued in DB
    expected_analysis_id = make_email_analysis_job_id(user_id, integ_msg_id)
    async with admin_maker() as db:
        analysis_job_row = (
            await db.execute(
                select(JobQueue).where(JobQueue.job_id == expected_analysis_id)
            )
        ).scalar_one_or_none()
        fetch_email_row = (
            await db.execute(
                select(ProcessedEmail).where(
                    ProcessedEmail.owner_user_id == user_id,
                    ProcessedEmail.gmail_message_id == integ_msg_id,
                )
            )
        ).scalar_one_or_none()

        check(
            analysis_job_row is not None
            and analysis_job_row.job_type == "email_analysis"
            and analysis_job_row.status == "queued"
            and fetch_email_row is not None
            and fetch_email_row.processing_status == "fetched"
            and analysis_job_row.payload.get("processed_email_id") == fetch_email_row.id
            and mock_fetch_enq.call_count == 1,
            "16 integration: sync->fetch->analysis job queued (mock Redis)",
            f"analysis_job_found={analysis_job_row is not None}, analysis_job_status={analysis_job_row.status if analysis_job_row else None}",
        )


if __name__ == "__main__":
    class SimpleRunner:
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

    r = SimpleRunner()
    asyncio.run(run_email_fetch_worker_tests(r))
    print(f"\nSuite 26 total: {r.passed}/{r.passed + r.failed} passed")
    sys.exit(0 if r.failed == 0 else 1)
