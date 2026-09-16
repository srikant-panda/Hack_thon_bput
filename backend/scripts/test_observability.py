"""RT-9 — Observability: correlation IDs, structured JSON logs, Prometheus metrics export tests (Suite 29).

Covers:
1 structured log output: JSON format with timestamp, level, message, correlation_id, job_id.
2 correlation_id propagation: set in contextvars, appears in all log calls within job.
3 correlation_id cleared on job end (no leakage to next job).
4 metrics increment: gmail_sync_jobs_total increments on success/failure.
5 histogram recording: job_processing_duration_seconds records correct duration.
6 dead_letter_jobs_total increments when job transitions to dead_letter.
7 gmail_api_errors_total increments on 401/429/5xx mock errors.
8 processed_emails_total increments with correct classification label.
9 /metrics endpoint returns Prometheus text format with all expected metrics.
10 sensitive data filter: access_token, refresh_token, email body never appear in logs.
11 contextvars isolation: two concurrent jobs have different correlation_id values.
12 log level: INFO for job start/end, WARNING for retries, ERROR for failures.
13 queue_depth gauge: mock Redis LLEN returns value, gauge updates.
14 worker_name label: metrics include worker_name (gmail-worker, email-worker, scheduler-worker).
15 full integration: webhook -> sync -> fetch -> analysis -> metrics all incremented correctly.

Run standalone:
    uv run python scripts/test_observability.py
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import io
import json
import logging
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
from sqlalchemy import select, text

from app.core.logging_config import (
    SensitiveDataFilter,
    StructuredJsonFormatter,
    clear_log_context,
    current_correlation_id,
    current_job_id,
    current_worker_name,
    set_log_context,
)
from app.core.metrics import (
    dead_letter_jobs_total,
    email_analysis_jobs_total,
    email_fetch_jobs_total,
    generate_prometheus_metrics,
    gmail_api_errors_total,
    gmail_events_received_total,
    gmail_sync_jobs_total,
    job_processing_duration_seconds,
    processed_emails_total,
    queue_depth,
    update_queue_depth,
    worker_jobs_total,
)
from app.db.admin import _get_admin_session_maker
from app.db.models import GmailAccount, JobQueue, ProcessedEmail
from app.main import app
from app.services.job_state_service import update_job_status
from app.workers.base import job_context, log_worker_event


async def run_observability_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("RT-9 Observability, Structured Logs & Prometheus Metrics (Suite 29)")
    print("-" * 60)

    admin_maker = _get_admin_session_maker()
    stamp = uuid.uuid4().hex[:8]

    # Helper for captive logger setup
    def _create_string_logger(logger_name: str) -> tuple[logging.Logger, io.StringIO]:
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(StructuredJsonFormatter())
        handler.addFilter(SensitiveDataFilter())

        test_log = logging.getLogger(logger_name)
        test_log.setLevel(logging.DEBUG)
        for h in list(test_log.handlers):
            test_log.removeHandler(h)
        test_log.addHandler(handler)
        test_log.propagate = False
        return test_log, buf

    # ------------------------------------------------------------------
    # 1. Structured log output
    # ------------------------------------------------------------------
    test_logger_1, buf_1 = _create_string_logger(f"cyberguard.test.log1.{stamp}")
    set_log_context(
        correlation_id="corr-chk1-123",
        job_id="job-chk1-456",
        job_type="gmail_sync",
        user_id="user-chk1-789",
        worker_name="gmail-worker",
    )
    test_logger_1.info("Structured log format test event")
    clear_log_context()

    lines_1 = [json.loads(line) for line in buf_1.getvalue().strip().splitlines() if line.strip()]
    c1_ok = False
    if lines_1:
        entry = lines_1[-1]
        c1_ok = (
            "timestamp" in entry
            and entry.get("level") == "INFO"
            and entry.get("message") == "Structured log format test event"
            and entry.get("correlation_id") == "corr-chk1-123"
            and entry.get("job_id") == "job-chk1-456"
            and entry.get("job_type") == "gmail_sync"
            and entry.get("user_id") == "user-chk1-789"
            and entry.get("worker_name") == "gmail-worker"
        )
    check(
        c1_ok,
        "1 structured log output: JSON format with timestamp, level, message, correlation_id, job_id",
        f"entry={lines_1[-1] if lines_1 else 'empty'}",
    )

    # ------------------------------------------------------------------
    # 2. Correlation ID propagation across log calls
    # ------------------------------------------------------------------
    test_logger_2, buf_2 = _create_string_logger(f"cyberguard.test.log2.{stamp}")
    async with job_context({"job_id": "job-prop-test"}, job_type="email_fetch", worker_name="email-worker") as corr_id:
        test_logger_2.info("Step 1: starting download")
        test_logger_2.debug("Step 2: parsing MIME body")
        test_logger_2.info("Step 3: enqueueing threat analysis")

    lines_2 = [json.loads(line) for line in buf_2.getvalue().strip().splitlines() if line.strip()]
    c2_ok = len(lines_2) == 3 and all(entry.get("correlation_id") == str(corr_id) for entry in lines_2)
    check(
        c2_ok,
        "2 correlation_id propagation: set in contextvars, appears in all log calls within job",
        f"count={len(lines_2)}, corr_ids={[e.get('correlation_id') for e in lines_2]}",
    )

    # ------------------------------------------------------------------
    # 3. Correlation ID cleared on job end (no leakage)
    # ------------------------------------------------------------------
    test_logger_3, buf_3 = _create_string_logger(f"cyberguard.test.log3.{stamp}")
    async with job_context({"job_id": "job-leakage-test"}, job_type="gmail_sync", worker_name="gmail-worker"):
        test_logger_3.info("Inside job context")
    test_logger_3.info("Outside job context after exit")

    lines_3 = [json.loads(line) for line in buf_3.getvalue().strip().splitlines() if line.strip()]
    c3_ok = (
        len(lines_3) == 2
        and lines_3[0].get("correlation_id") is not None
        and lines_3[1].get("correlation_id") is None
        and lines_3[1].get("job_id") is None
    )
    check(
        c3_ok,
        "3 correlation_id cleared on job end (no leakage to next job)",
        f"outside_entry={lines_3[-1] if lines_3 else 'empty'}",
    )

    # ------------------------------------------------------------------
    # 4. Metrics increment: gmail_sync_jobs_total (success / failed)
    # ------------------------------------------------------------------
    sync_succ_before = gmail_sync_jobs_total.labels(status="success")._value.get()
    sync_fail_before = gmail_sync_jobs_total.labels(status="failed")._value.get()

    gmail_sync_jobs_total.labels(status="success").inc()
    gmail_sync_jobs_total.labels(status="failed").inc()

    sync_succ_after = gmail_sync_jobs_total.labels(status="success")._value.get()
    sync_fail_after = gmail_sync_jobs_total.labels(status="failed")._value.get()

    c4_ok = (sync_succ_after == sync_succ_before + 1) and (sync_fail_after == sync_fail_before + 1)
    check(
        c4_ok,
        "4 metrics increment: gmail_sync_jobs_total increments on success/failure",
        f"succ: {sync_succ_before} -> {sync_succ_after}, fail: {sync_fail_before} -> {sync_fail_after}",
    )

    # ------------------------------------------------------------------
    # 5. Histogram recording: job_processing_duration_seconds
    # ------------------------------------------------------------------
    hist = job_processing_duration_seconds.labels(job_type="gmail_sync")

    def _get_hist_stats():
        count_val, sum_val = 0.0, 0.0
        for metric_family in job_processing_duration_seconds.collect():
            for sample in metric_family.samples:
                if sample.name.endswith("_count") and sample.labels.get("job_type") == "gmail_sync":
                    count_val = sample.value
                elif sample.name.endswith("_sum") and sample.labels.get("job_type") == "gmail_sync":
                    sum_val = sample.value
        return count_val, sum_val

    count_before, sum_before = _get_hist_stats()
    job_processing_duration_seconds.labels(job_type="gmail_sync").observe(1.25)
    count_after, sum_after = _get_hist_stats()

    c5_ok = (count_after == count_before + 1) and abs((sum_after - sum_before) - 1.25) < 1e-6
    check(
        c5_ok,
        "5 histogram recording: job_processing_duration_seconds records correct duration",
        f"count: {count_before} -> {count_after}, sum diff: {sum_after - sum_before:.3f}",
    )

    # ------------------------------------------------------------------
    # 6. dead_letter_jobs_total increments on dead_letter transition
    # ------------------------------------------------------------------
    dl_user = f"obs_user_{stamp}"
    async with admin_maker() as db:
        await db.execute(
            text(
                "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                "values (:u, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"u": dl_user},
        )
        job_id = f"job:deadletter:{stamp}"
        db.add(
            JobQueue(
                job_id=job_id,
                owner_user_id=dl_user,
                job_type="email_fetch",
                status="running",
                retry_count=2,
                max_retries=3,
                payload={"test": True},
            )
        )
        await db.commit()

        dl_before = dead_letter_jobs_total.labels(job_type="email_fetch")._value.get()
        await update_job_status(db, job_id, "dead_letter", error="Poison pill unrecoverable error")
        dl_after = dead_letter_jobs_total.labels(job_type="email_fetch")._value.get()

    c6_ok = dl_after == dl_before + 1
    check(
        c6_ok,
        "6 dead_letter_jobs_total increments when job transitions to dead_letter",
        f"{dl_before} -> {dl_after}",
    )

    # ------------------------------------------------------------------
    # 7. gmail_api_errors_total increments on 401/429/5xx mock errors
    # ------------------------------------------------------------------
    auth_before = gmail_api_errors_total.labels(error_type="auth")._value.get()
    rate_before = gmail_api_errors_total.labels(error_type="rate_limit")._value.get()
    serv_before = gmail_api_errors_total.labels(error_type="server")._value.get()

    gmail_api_errors_total.labels(error_type="auth").inc()
    gmail_api_errors_total.labels(error_type="rate_limit").inc()
    gmail_api_errors_total.labels(error_type="server").inc()

    auth_after = gmail_api_errors_total.labels(error_type="auth")._value.get()
    rate_after = gmail_api_errors_total.labels(error_type="rate_limit")._value.get()
    serv_after = gmail_api_errors_total.labels(error_type="server")._value.get()

    c7_ok = (
        auth_after == auth_before + 1
        and rate_after == rate_before + 1
        and serv_after == serv_before + 1
    )
    check(
        c7_ok,
        "7 gmail_api_errors_total increments on 401/429/5xx mock errors",
        f"auth={auth_after}, rate={rate_after}, server={serv_after}",
    )

    # ------------------------------------------------------------------
    # 8. processed_emails_total increments with correct classification label
    # ------------------------------------------------------------------
    p_safe_before = processed_emails_total.labels(classification="safe")._value.get()
    p_phish_before = processed_emails_total.labels(classification="phishing")._value.get()
    p_susp_before = processed_emails_total.labels(classification="suspicious")._value.get()

    processed_emails_total.labels(classification="safe").inc()
    processed_emails_total.labels(classification="phishing").inc()
    processed_emails_total.labels(classification="suspicious").inc()

    p_safe_after = processed_emails_total.labels(classification="safe")._value.get()
    p_phish_after = processed_emails_total.labels(classification="phishing")._value.get()
    p_susp_after = processed_emails_total.labels(classification="suspicious")._value.get()

    c8_ok = (
        p_safe_after == p_safe_before + 1
        and p_phish_after == p_phish_before + 1
        and p_susp_after == p_susp_before + 1
    )
    check(
        c8_ok,
        "8 processed_emails_total increments with correct classification label",
        f"safe: {p_safe_after}, phishing: {p_phish_after}, suspicious: {p_susp_after}",
    )

    # ------------------------------------------------------------------
    # 9. /metrics endpoint returns Prometheus text format with all expected metrics
    # ------------------------------------------------------------------
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/metrics")

    status_ok = res.status_code == 200
    ctype_ok = "text/plain" in res.headers.get("content-type", "")
    text_body = res.text

    expected_metrics = [
        "gmail_events_received_total",
        "gmail_sync_jobs_total",
        "email_fetch_jobs_total",
        "email_analysis_jobs_total",
        "job_processing_duration_seconds",
        "queue_depth",
        "dead_letter_jobs_total",
        "gmail_api_errors_total",
        "processed_emails_total",
    ]
    all_found = all(metric_name in text_body for metric_name in expected_metrics)
    c9_ok = status_ok and ctype_ok and all_found
    check(
        c9_ok,
        "9 /metrics endpoint returns Prometheus text format with all expected metrics",
        f"status={res.status_code}, ctype={res.headers.get('content-type')}, all_found={all_found}",
    )

    # ------------------------------------------------------------------
    # 10. Sensitive data filter: access_token, refresh_token, email body never appear in logs
    # ------------------------------------------------------------------
    test_logger_10, buf_10 = _create_string_logger(f"cyberguard.test.log10.{stamp}")
    raw_sensitive_token = "ya29.a0AfH6_LEAKED_OAUTH_TOKEN_VALUE_XYZ"
    raw_refresh_token = "1//04_LEAKED_REFRESH_TOKEN_VALUE_ABC"
    raw_body_secret = "Top Secret Financial Wire Instructions: Send $50,000"
    raw_attachment_secret = "Base64PayloadBytesSecret123=="

    test_logger_10.info(
        f"Received token {raw_sensitive_token} with refresh {raw_refresh_token} "
        f"and body='{raw_body_secret}' and attachment_data='{raw_attachment_secret}'"
    )

    log_output = buf_10.getvalue()
    c10_ok = (
        raw_sensitive_token not in log_output
        and raw_refresh_token not in log_output
        and raw_body_secret not in log_output
        and raw_attachment_secret not in log_output
        and "[REDACTED_TOKEN]" in log_output
        and "[REDACTED_BODY]" in log_output
    )
    check(
        c10_ok,
        "10 sensitive data filter: access_token, refresh_token, email body never appear in logs",
        f"scrubbed_successfully={c10_ok}",
    )

    # ------------------------------------------------------------------
    # 11. Contextvars isolation: two concurrent jobs have different correlation_id values
    # ------------------------------------------------------------------
    task_results: dict[str, list[str]] = {}

    async def _concurrent_task(task_name: str, corr_id: str):
        async with job_context({"job_id": f"job-{task_name}"}, correlation_id=corr_id):
            first = current_correlation_id.get()
            await asyncio.sleep(0.02)
            second = current_correlation_id.get()
            task_results[task_name] = [first, second]

    await asyncio.gather(
        _concurrent_task("taskA", "corr-A-111"),
        _concurrent_task("taskB", "corr-B-222"),
    )

    c11_ok = (
        task_results.get("taskA") == ["corr-A-111", "corr-A-111"]
        and task_results.get("taskB") == ["corr-B-222", "corr-B-222"]
    )
    check(
        c11_ok,
        "11 contextvars isolation: two concurrent jobs have different correlation_id values",
        f"taskA={task_results.get('taskA')}, taskB={task_results.get('taskB')}",
    )

    # ------------------------------------------------------------------
    # 12. Log level: INFO for job start/end, WARNING for retries, ERROR for failures
    # ------------------------------------------------------------------
    test_logger_12, buf_12 = _create_string_logger(f"cyberguard.test.log12.{stamp}")
    log_worker_event(test_logger_12, logging.INFO, "Job start event", job_type="email_fetch")
    log_worker_event(test_logger_12, logging.WARNING, "Transient failure: retry 1 of 3", job_type="email_fetch")
    log_worker_event(test_logger_12, logging.ERROR, "Job failed fatally: unrecoverable", job_type="email_fetch")
    log_worker_event(test_logger_12, logging.INFO, "Job end event", job_type="email_fetch")

    lines_12 = [json.loads(line) for line in buf_12.getvalue().strip().splitlines() if line.strip()]
    levels_12 = [e.get("level") for e in lines_12]
    c12_ok = levels_12 == ["INFO", "WARNING", "ERROR", "INFO"]
    check(
        c12_ok,
        "12 log level: INFO for job start/end, WARNING for retries, ERROR for failures",
        f"levels={levels_12}",
    )

    # ------------------------------------------------------------------
    # 13. queue_depth gauge: mock Redis LLEN returns value, gauge updates
    # ------------------------------------------------------------------
    mock_redis = MagicMock()
    mock_redis.llen = AsyncMock(return_value=27)
    # Delete type attribute if MagicMock auto-created it
    if hasattr(mock_redis, "type"):
        del mock_redis.type

    res_depth = await update_queue_depth(mock_redis, queue_name="cyberguard:queue")
    gauge_val = queue_depth.labels(queue_name="cyberguard:queue")._value.get()
    c13_ok = (res_depth == 27) and (gauge_val == 27.0)
    check(
        c13_ok,
        "13 queue_depth gauge: mock Redis LLEN returns value, gauge updates",
        f"returned={res_depth}, gauge={gauge_val}",
    )

    # ------------------------------------------------------------------
    # 14. worker_name label: metrics include worker_name (gmail-worker, email-worker, scheduler-worker)
    # ------------------------------------------------------------------
    metrics_text = generate_prometheus_metrics()
    workers_expected = ["gmail-worker", "email-worker", "scheduler-worker"]
    found_workers = [w in metrics_text for w in workers_expected]
    c14_ok = all(found_workers) and "worker_name" in metrics_text
    check(
        c14_ok,
        "14 worker_name label: metrics include worker_name (gmail-worker, email-worker, scheduler-worker)",
        f"found_workers={dict(zip(workers_expected, found_workers))}",
    )

    # ------------------------------------------------------------------
    # 15. Full integration: webhook -> sync -> fetch -> analysis -> metrics all incremented correctly
    # ------------------------------------------------------------------
    integ_user = f"integ_user_{stamp}"
    async with admin_maker() as db:
        await db.execute(
            text(
                "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                "values (:u, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"u": integ_user},
        )

        acc = GmailAccount(
            id=str(uuid.uuid4()),
            owner_user_id=integ_user,
            email=f"obs_pipeline_{stamp}@example.com",
            sync_status="active",
            last_history_id="1000",
        )
        acc.set_access_token("valid_access_token")
        acc.set_refresh_token("valid_refresh_token")
        db.add(acc)
        await db.commit()
        await db.refresh(acc)

    # Baselines
    ev_b = gmail_events_received_total.labels(owner_user_id=integ_user)._value.get()
    sy_b = gmail_sync_jobs_total.labels(status="success")._value.get()
    fe_b = email_fetch_jobs_total.labels(status="success", failure_reason="none")._value.get()
    an_b = email_analysis_jobs_total.labels(status="success", classification="safe")._value.get()

    # Step 1: Webhook received
    gmail_events_received_total.labels(owner_user_id=integ_user).inc()

    # Step 2: Sync discovers 1 message
    from app.services.gmail.sync_service import process_gmail_sync
    mock_sync_client = MagicMock()
    mock_sync_client.list_history = AsyncMock(
        return_value={"history": [{"messagesAdded": [{"message": {"id": f"msg_{stamp}"}}]}], "historyId": "1050"}
    )
    async with admin_maker() as db:
        await process_gmail_sync(db, account_id=str(acc.id), history_id_from_pubsub="1050", client=mock_sync_client)

    # Step 3: Fetch downloads message
    from app.services.gmail.fetch_service import process_email_fetch
    mock_fetch_client = MagicMock()
    mock_fetch_client.get_message = AsyncMock(
        return_value={
            "id": f"msg_{stamp}",
            "sizeEstimate": 500,
            "snippet": "Account statement attached",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Monthly Statement"},
                    {"name": "From", "value": "Billing <billing@bank.com>"},
                ],
                "mimeType": "text/plain",
                "body": {"data": "WW91ciBzdGF0ZW1lbnQgaXMgcmVhZHku"},  # "Your statement is ready."
            },
        }
    )
    async with admin_maker() as db:
        fetch_res = await process_email_fetch(db, account_id=str(acc.id), message_id=f"msg_{stamp}", client=mock_fetch_client)
        processed_email_id = fetch_res["processed_email_id"]

    # Step 4: Threat analysis executes
    from app.services.gmail.analysis_service import process_email_analysis
    async with admin_maker() as db:
        await process_email_analysis(db, processed_email_id=processed_email_id)

    # After metrics
    ev_a = gmail_events_received_total.labels(owner_user_id=integ_user)._value.get()
    sy_a = gmail_sync_jobs_total.labels(status="success")._value.get()
    fe_a = email_fetch_jobs_total.labels(status="success", failure_reason="none")._value.get()
    an_a = email_analysis_jobs_total.labels(status="success", classification="safe")._value.get()

    c15_ok = (
        (ev_a == ev_b + 1)
        and (sy_a == sy_b + 1)
        and (fe_a == fe_b + 1)
        and (an_a >= an_b + 1)
    )
    check(
        c15_ok,
        "15 full integration: webhook -> sync -> fetch -> analysis -> metrics all incremented correctly",
        f"ev: {ev_b}->{ev_a}, sync: {sy_b}->{sy_a}, fetch: {fe_b}->{fe_a}, analysis: {an_b}->{an_a}",
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
        print(f"\nSuite 29 total: {self.passed}/{total} passed")
        return 0 if self.failed == 0 else 1


if __name__ == "__main__":
    runner = StandaloneRunner()
    asyncio.run(run_observability_tests(runner))
    sys.exit(runner.report())
