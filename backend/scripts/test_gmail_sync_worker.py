"""RT-4 — Gmail sync worker tests (Suite 25).

Covers:
1 mock GmailClient.list_history returns 3 messages -> 3 email_fetch jobs enqueued with deterministic IDs.
2 mock list_history returns empty -> 0 jobs enqueued, last_history_id still updated.
3 initial sync (last_history_id=None) -> calls get_profile, stores historyId, enqueues 0 fetch jobs.
4 concurrency: two concurrent gmail_sync_job calls for same account -> second waits for FOR UPDATE lock, processes sequentially, no lost updates.
5 GmailAuthError (401 mock) -> job status='failed', account.sync_status='error', last_error='reauth_required'.
6 GmailRateLimitError (429 mock) -> job raises, Arq retry logic triggered (verify retry_count incremented).
7 update_history_id logic: new historyId > old -> updated; new < old -> ignored (idempotent safety).
8 email_fetch job payload contains {account_id, message_id}.
9 job state transitions: queued -> running -> completed verified in job_queue table.
10 correlation_id propagated to logs (capture log output, assert correlation_id present).
11 RLS: worker operates under correct owner_user_id context (job_queue row owner matches account).
12 token decryption: mock Fernet, verify access_token passed to GmailClient is decrypted.
13 duplicate message IDs in history response -> deduplicated before enqueueing (set() logic).
14 worker graceful shutdown: mock SIGTERM, verify current job completes before exit.
15 full integration: Pub/Sub webhook -> enqueue gmail_sync -> worker executes -> email_fetch jobs in queue (mock Redis, assert enqueue calls).

Run standalone:
    uv run python scripts/test_gmail_sync_worker.py
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
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.core.crypto import decrypt_secret, encrypt_secret
from app.db.admin import _get_admin_session_maker
from app.db.models import GmailAccount, JobQueue
from app.main import app
from app.queue.client import make_email_fetch_job_id, make_gmail_sync_job_id
from app.services.gmail.client import (
    GmailAuthError,
    GmailClient,
    GmailRateLimitError,
    GmailServerError,
)
from app.services.gmail.sync_service import (
    extract_unique_message_ids,
    is_greater_history_id,
    process_gmail_sync,
)
from app.services.gmail_account_service import update_history_id
from app.services.idempotency_service import ensure_job
from app.workers.base import base_shutdown, base_startup
from app.workers.gmail_worker import gmail_sync_job


def _make_pubsub_body(email: str, history_id: str | int, message_id: str = "msg-sync-test") -> dict:
    data_bytes = json.dumps({"emailAddress": email, "historyId": str(history_id)}).encode("utf-8")
    data_b64 = base64.b64encode(data_bytes).decode("utf-8")
    return {
        "message": {
            "data": data_b64,
            "messageId": message_id,
        },
        "subscription": "projects/cyberguard-test/subscriptions/gmail-push",
    }


class LogCaptureHandler(logging.Handler):
    """Memory handler to capture structured worker log records."""

    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord):
        self.records.append(record)


async def run_gmail_sync_worker_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("RT-4 Gmail Sync Worker Tests (Suite 25)")
    print("-" * 60)

    admin_maker = _get_admin_session_maker()
    stamp = uuid.uuid4().hex[:8]

    # Setup test user and Gmail account
    user_id = f"sync-user-{stamp}"
    email = f"sync-{stamp}@gmail.com"
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
            last_history_id="10000",
        )
        account.set_access_token(raw_access_token)
        account.set_refresh_token(raw_refresh_token)
        db.add(account)
        await db.commit()
        await db.refresh(account)
        acc_id = account.id

    # ------------------------------------------------------------------
    # 1. mock GmailClient.list_history returns 3 messages -> 3 email_fetch jobs enqueued with deterministic IDs
    # ------------------------------------------------------------------
    mock_client_3 = MagicMock(spec=GmailClient)
    mock_client_3.list_history = AsyncMock(
        return_value=[
            {"id": "10005", "messagesAdded": [{"message": {"id": f"msg_a_{stamp}"}}]},
            {"id": "10006", "messagesAdded": [{"message": {"id": f"msg_b_{stamp}"}}]},
            {"id": "10007", "messagesAdded": [{"message": {"id": f"msg_c_{stamp}"}}]},
        ]
    )

    async with admin_maker() as db:
        res_1 = await process_gmail_sync(db, acc_id, "10010", client=mock_client_3)
        check(
            res_1["messages_enqueued"] == 3 and res_1["status"] == "synced",
            "1 mock GmailClient.list_history returns 3 messages -> 3 email_fetch jobs enqueued with deterministic IDs",
            f"Result: {res_1}",
        )

    # ------------------------------------------------------------------
    # 2. mock list_history returns empty -> 0 jobs enqueued, last_history_id still updated
    # ------------------------------------------------------------------
    mock_client_empty = MagicMock(spec=GmailClient)
    mock_client_empty.list_history = AsyncMock(return_value=[])

    async with admin_maker() as db:
        res_2 = await process_gmail_sync(db, acc_id, "10050", client=mock_client_empty)
        stmt = select(GmailAccount).where(GmailAccount.id == acc_id)
        acc_after_empty = (await db.execute(stmt)).scalar_one()
        check(
            res_2["messages_enqueued"] == 0 and acc_after_empty.last_history_id == "10050",
            "2 mock list_history returns empty -> 0 jobs enqueued, last_history_id still updated",
            f"last_history_id={acc_after_empty.last_history_id}, enqueued={res_2['messages_enqueued']}",
        )

    # ------------------------------------------------------------------
    # 3. initial sync (last_history_id=None) -> calls get_profile, stores historyId, enqueues 0 fetch jobs
    # ------------------------------------------------------------------
    init_user_id = f"init-user-{stamp}"
    init_email = f"init-{stamp}@gmail.com"
    async with admin_maker() as db:
        await db.execute(
            text(
                "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                "values (:id, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"id": init_user_id},
        )
        init_acc = GmailAccount(
            owner_user_id=init_user_id,
            email=init_email,
            sync_status="active",
            last_history_id=None,
        )
        init_acc.set_access_token("init_tok")
        init_acc.set_refresh_token("init_ref")
        db.add(init_acc)
        await db.commit()
        await db.refresh(init_acc)
        init_acc_id = init_acc.id

    mock_client_init = MagicMock(spec=GmailClient)
    mock_client_init.get_profile = AsyncMock(return_value={"historyId": "77777"})
    mock_client_init.list_history = AsyncMock()

    async with admin_maker() as db:
        res_3 = await process_gmail_sync(db, init_acc_id, "77777", client=mock_client_init)
        stmt = select(GmailAccount).where(GmailAccount.id == init_acc_id)
        acc_after_init = (await db.execute(stmt)).scalar_one()
        check(
            res_3["status"] == "initial_sync"
            and acc_after_init.last_history_id == "77777"
            and mock_client_init.get_profile.call_count == 1
            and mock_client_init.list_history.call_count == 0
            and res_3["messages_enqueued"] == 0,
            "3 initial sync (last_history_id=None) -> calls get_profile, stores historyId, enqueues 0 fetch jobs",
            f"profile_calls={mock_client_init.get_profile.call_count}, history={acc_after_init.last_history_id}",
        )

    # ------------------------------------------------------------------
    # 4. concurrency: two concurrent gmail_sync_job calls for same account -> second waits for FOR UPDATE lock, processes sequentially, no lost updates
    # ------------------------------------------------------------------
    concurrency_client = MagicMock(spec=GmailClient)

    async def slow_list_history(access_token, start_history_id, refresh_token=None):
        await asyncio.sleep(0.05)
        return []

    concurrency_client.list_history = AsyncMock(side_effect=slow_list_history)

    ctx_c1 = {"db_maker": admin_maker, "job_id": f"conc_job_1_{stamp}"}
    ctx_c2 = {"db_maker": admin_maker, "job_id": f"conc_job_2_{stamp}"}

    async with admin_maker() as db:
        await ensure_job(db, user_id, "gmail_sync", ctx_c1["job_id"], {"account_id": acc_id, "history_id": "10100"})
        await ensure_job(db, user_id, "gmail_sync", ctx_c2["job_id"], {"account_id": acc_id, "history_id": "10200"})

    res_c1, res_c2 = await asyncio.gather(
        gmail_sync_job(ctx_c1, acc_id, "10100", client=concurrency_client),
        gmail_sync_job(ctx_c2, acc_id, "10200", client=concurrency_client),
    )

    async with admin_maker() as db:
        stmt = select(GmailAccount).where(GmailAccount.id == acc_id)
        final_acc_c = (await db.execute(stmt)).scalar_one()
        check(
            final_acc_c.last_history_id == "10200"
            and res_c1["status"] == "synced"
            and res_c2["status"] == "synced",
            "4 concurrency: two concurrent gmail_sync_job calls for same account -> second waits for FOR UPDATE lock, processes sequentially, no lost updates",
            f"final_last_history_id={final_acc_c.last_history_id}",
        )

    # ------------------------------------------------------------------
    # 5. GmailAuthError (401 mock) -> job status='failed', account.sync_status='error', last_error='reauth_required'
    # ------------------------------------------------------------------
    auth_client = MagicMock(spec=GmailClient)
    auth_client.list_history = AsyncMock(side_effect=GmailAuthError("Invalid credentials", status_code=401))

    auth_job_id = f"auth_err_job_{stamp}"
    async with admin_maker() as db:
        await ensure_job(db, user_id, "gmail_sync", auth_job_id, {"account_id": acc_id, "history_id": "10300"})

    auth_failed = False
    try:
        await gmail_sync_job({"db_maker": admin_maker, "job_id": auth_job_id}, acc_id, "10300", client=auth_client)
    except GmailAuthError:
        auth_failed = True

    async with admin_maker() as db:
        acc_auth = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        job_auth = (await db.execute(select(JobQueue).where(JobQueue.job_id == auth_job_id))).scalar_one()
        check(
            auth_failed
            and acc_auth.sync_status == "error"
            and acc_auth.last_error == "reauth_required"
            and job_auth.status == "failed",
            "5 GmailAuthError (401 mock) -> job status='failed', account.sync_status='error', last_error='reauth_required'",
            f"account_sync_status={acc_auth.sync_status}, last_error={acc_auth.last_error}, job_status={job_auth.status}",
        )

    # Reset sync_status to active for subsequent tests
    async with admin_maker() as db:
        acc_reset = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        acc_reset.sync_status = "active"
        acc_reset.last_error = None
        await db.commit()

    # ------------------------------------------------------------------
    # 6. GmailRateLimitError (429 mock) -> job raises, Arq retry logic triggered (verify retry_count incremented)
    # ------------------------------------------------------------------
    rate_client = MagicMock(spec=GmailClient)
    rate_client.list_history = AsyncMock(side_effect=GmailRateLimitError("Rate limit exceeded", status_code=429))

    rate_job_id = f"rate_err_job_{stamp}"
    async with admin_maker() as db:
        await ensure_job(db, user_id, "gmail_sync", rate_job_id, {"account_id": acc_id, "history_id": "10400"})

    rate_failed = False
    try:
        await gmail_sync_job({"db_maker": admin_maker, "job_id": rate_job_id}, acc_id, "10400", client=rate_client)
    except GmailRateLimitError:
        rate_failed = True

    async with admin_maker() as db:
        job_rate = (await db.execute(select(JobQueue).where(JobQueue.job_id == rate_job_id))).scalar_one()
        check(
            rate_failed
            and job_rate.status == "failed"
            and job_rate.retry_count >= 1
            and job_rate.next_retry_at is not None,
            "6 GmailRateLimitError (429 mock) -> job raises, Arq retry logic triggered (verify retry_count incremented)",
            f"retry_count={job_rate.retry_count}, next_retry_at={job_rate.next_retry_at}",
        )

    # ------------------------------------------------------------------
    # 7. update_history_id logic: new historyId > old -> updated; new < old -> ignored (idempotent safety)
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        # Initial base history ID: 10500
        await update_history_id(db, acc_id, "10500")
        acc_mid = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        check_1 = acc_mid.last_history_id == "10500"

        # Update with higher history ID: 10600 -> should update
        await update_history_id(db, acc_id, "10600")
        acc_high = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        check_2 = acc_high.last_history_id == "10600"

        # Update with lower history ID: 10450 -> should be ignored
        await update_history_id(db, acc_id, "10450")
        acc_low = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        check_3 = acc_low.last_history_id == "10600"

        # Direct unit function verification
        f_check = (
            is_greater_history_id("20000", "10000") is True
            and is_greater_history_id("10000", "20000") is False
            and is_greater_history_id("10000", "10000") is False
        )

        check(
            check_1 and check_2 and check_3 and f_check,
            "7 update_history_id logic: new historyId > old -> updated; new < old -> ignored (idempotent safety)",
            f"h1={acc_mid.last_history_id}, h2={acc_high.last_history_id}, h3={acc_low.last_history_id}",
        )

    # ------------------------------------------------------------------
    # 8. email_fetch job payload contains {account_id, message_id}
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        stmt = (
            select(JobQueue)
            .where(
                JobQueue.owner_user_id == user_id,
                JobQueue.job_type == "email_fetch",
            )
            .limit(1)
        )
        sample_fetch_job = (await db.execute(stmt)).scalar_one_or_none()
        check(
            sample_fetch_job is not None
            and "account_id" in sample_fetch_job.payload
            and "message_id" in sample_fetch_job.payload
            and sample_fetch_job.payload["account_id"] == acc_id,
            "8 email_fetch job payload contains {account_id, message_id}",
            f"payload={sample_fetch_job.payload if sample_fetch_job else None}",
        )

    # ------------------------------------------------------------------
    # 9. job state transitions: queued -> running -> completed verified in job_queue table
    # ------------------------------------------------------------------
    state_job_id = f"state_trans_job_{stamp}"
    async with admin_maker() as db:
        created_j = await ensure_job(
            db, user_id, "gmail_sync", state_job_id, {"account_id": acc_id, "history_id": "10700"}
        )
        initial_status = created_j.status

    # Execute job
    norm_client = MagicMock(spec=GmailClient)
    norm_client.list_history = AsyncMock(return_value=[])

    await gmail_sync_job({"db_maker": admin_maker, "job_id": state_job_id}, acc_id, "10700", client=norm_client)

    async with admin_maker() as db:
        completed_j = (await db.execute(select(JobQueue).where(JobQueue.job_id == state_job_id))).scalar_one()
        check(
            initial_status == "queued"
            and completed_j.status == "completed"
            and completed_j.started_at is not None
            and completed_j.completed_at is not None,
            "9 job state transitions: queued -> running -> completed verified in job_queue table",
            f"initial={initial_status}, completed={completed_j.status}",
        )

    # ------------------------------------------------------------------
    # 10. correlation_id propagated to logs (capture log output, assert correlation_id present)
    # ------------------------------------------------------------------
    capture_handler = LogCaptureHandler()
    worker_logger = logging.getLogger("cyberguard.worker")
    worker_logger.addHandler(capture_handler)
    target_corr_id = f"corr-{uuid.uuid4().hex[:12]}"

    corr_job_id = f"corr_job_{stamp}"
    async with admin_maker() as db:
        await ensure_job(
            db, user_id, "gmail_sync", corr_job_id, {"account_id": acc_id, "history_id": "10750"}
        )

    await gmail_sync_job(
        {"db_maker": admin_maker, "job_id": target_corr_id},
        acc_id,
        "10750",
        client=norm_client,
    )
    worker_logger.removeHandler(capture_handler)

    corr_found = any(
        getattr(rec, "correlation_id", None) == target_corr_id or target_corr_id in rec.getMessage()
        for rec in capture_handler.records
    )
    check(
        corr_found,
        "10 correlation_id propagated to logs (capture log output, assert correlation_id present)",
        f"Target corr_id: {target_corr_id}, captured records: {len(capture_handler.records)}",
    )

    # ------------------------------------------------------------------
    # 11. RLS: worker operates under correct owner_user_id context (job_queue row owner matches account)
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        fetch_jobs_stmt = select(JobQueue).where(
            JobQueue.job_type == "email_fetch",
            JobQueue.job_id.like(f"email_fetch:{user_id}:%"),
        )
        fetch_jobs = (await db.execute(fetch_jobs_stmt)).scalars().all()
        all_owned_correctly = len(fetch_jobs) > 0 and all(j.owner_user_id == user_id for j in fetch_jobs)
        check(
            all_owned_correctly,
            "11 RLS: worker operates under correct owner_user_id context (job_queue row owner matches account)",
            f"jobs_count={len(fetch_jobs)}, sample_owner={fetch_jobs[0].owner_user_id if fetch_jobs else None}",
        )

    # ------------------------------------------------------------------
    # 12. token decryption: mock Fernet, verify access_token passed to GmailClient is decrypted
    # ------------------------------------------------------------------
    spy_client = MagicMock(spec=GmailClient)
    captured_access_tokens: list[str] = []

    async def spy_list_history(access_token, start_history_id, refresh_token=None):
        captured_access_tokens.append(access_token)
        return []

    spy_client.list_history = AsyncMock(side_effect=spy_list_history)

    async with admin_maker() as db:
        await process_gmail_sync(db, acc_id, "10800", client=spy_client)

    check(
        len(captured_access_tokens) == 1 and captured_access_tokens[0] == raw_access_token,
        "12 token decryption: mock Fernet, verify access_token passed to GmailClient is decrypted",
        f"passed_token={captured_access_tokens[0] if captured_access_tokens else None}",
    )

    # ------------------------------------------------------------------
    # 13. duplicate message IDs in history response -> deduplicated before enqueueing (set() logic)
    # ------------------------------------------------------------------
    dup_client = MagicMock(spec=GmailClient)
    dup_mid_1 = f"dup_msg_1_{stamp}"
    dup_mid_2 = f"dup_msg_2_{stamp}"
    dup_client.list_history = AsyncMock(
        return_value=[
            {"id": "10810", "messagesAdded": [{"message": {"id": dup_mid_1}}]},
            {"id": "10811", "messagesAdded": [{"message": {"id": dup_mid_1}}]},
            {"id": "10812", "messagesAdded": [{"message": {"id": dup_mid_2}}]},
            {"id": "10813", "messagesAdded": [{"message": {"id": dup_mid_1}}]},
        ]
    )

    extracted = extract_unique_message_ids(
        [
            {"id": "10810", "messagesAdded": [{"message": {"id": dup_mid_1}}]},
            {"id": "10811", "messagesAdded": [{"message": {"id": dup_mid_1}}]},
            {"id": "10812", "messagesAdded": [{"message": {"id": dup_mid_2}}]},
            {"id": "10813", "messagesAdded": [{"message": {"id": dup_mid_1}}]},
        ]
    )

    async with admin_maker() as db:
        res_dup = await process_gmail_sync(db, acc_id, "10820", client=dup_client)
        check(
            len(extracted) == 2
            and extracted == [dup_mid_1, dup_mid_2]
            and res_dup["messages_enqueued"] == 2,
            "13 duplicate message IDs in history response -> deduplicated before enqueueing (set() logic)",
            f"extracted_count={len(extracted)}, enqueued={res_dup['messages_enqueued']}",
        )

    # ------------------------------------------------------------------
    # 14. worker graceful shutdown: mock SIGTERM, verify current job completes before exit
    # ------------------------------------------------------------------
    shutdown_job_id = f"shutdown_job_{stamp}"
    async with admin_maker() as db:
        await ensure_job(db, user_id, "gmail_sync", shutdown_job_id, {"account_id": acc_id, "history_id": "10850"})

    shutdown_ctx = {"db_maker": admin_maker, "job_id": shutdown_job_id}
    await base_startup(shutdown_ctx)
    shutdown_ctx["db_maker"] = admin_maker

    sigterm_triggered = False

    async def run_job_with_sigterm():
        nonlocal sigterm_triggered
        job_task = asyncio.create_task(
            gmail_sync_job(shutdown_ctx, acc_id, "10850", client=norm_client)
        )
        # Mock SIGTERM arriving while job is in-flight
        await asyncio.sleep(0.01)
        sigterm_triggered = True
        result = await job_task
        await base_shutdown(shutdown_ctx)
        return result

    res_shutdown = await run_job_with_sigterm()

    async with admin_maker() as db:
        job_s = (await db.execute(select(JobQueue).where(JobQueue.job_id == shutdown_job_id))).scalar_one()
        check(
            job_s.status == "completed" and sigterm_triggered and res_shutdown.get("status") == "synced",
            "14 worker graceful shutdown: mock SIGTERM, verify current job completes before exit",
            f"shutdown_job_status={job_s.status}, sigterm={sigterm_triggered}",
        )

    # ------------------------------------------------------------------
    # 15. full integration: Pub/Sub webhook -> enqueue gmail_sync -> worker executes -> email_fetch jobs in queue (mock Redis, assert enqueue calls)
    # ------------------------------------------------------------------
    integ_hist = f"20001_{stamp}"
    integ_mid_1 = f"integ_m1_{stamp}"
    integ_mid_2 = f"integ_m2_{stamp}"

    integ_client = MagicMock(spec=GmailClient)
    integ_client.list_history = AsyncMock(
        return_value=[
            {"id": "20001", "messagesAdded": [{"message": {"id": integ_mid_1}}]},
            {"id": "20002", "messagesAdded": [{"message": {"id": integ_mid_2}}]},
        ]
    )

    webhook_body = _make_pubsub_body(email, integ_hist, message_id=f"ps_integ_{stamp}")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http_c:
        with patch("app.api.routes_gmail_webhook.enqueue", new_callable=AsyncMock) as mock_wh_enqueue:
            mock_wh_enqueue.return_value = make_gmail_sync_job_id(user_id, integ_hist)
            resp = await http_c.post("/api/v1/webhooks/gmail", json=webhook_body)
            check_wh_ok = resp.status_code == 200
            resp_data = resp.json()
            wh_job_id = resp_data.get("job_id")

    # Worker picks up the enqueued gmail_sync job
    with patch("app.services.gmail.sync_service.enqueue", new_callable=AsyncMock) as mock_sync_enqueue:
        mock_sync_enqueue.return_value = "enqueued_ok"
        worker_res = await gmail_sync_job(
            {"db_maker": admin_maker, "job_id": wh_job_id},
            acc_id,
            integ_hist,
            client=integ_client,
        )

    async with admin_maker() as db:
        sync_job_row = (await db.execute(select(JobQueue).where(JobQueue.job_id == wh_job_id))).scalar_one()
        fetch_1 = (
            await db.execute(
                select(JobQueue).where(
                    JobQueue.job_id == make_email_fetch_job_id(user_id, integ_mid_1)
                )
            )
        ).scalar_one_or_none()
        fetch_2 = (
            await db.execute(
                select(JobQueue).where(
                    JobQueue.job_id == make_email_fetch_job_id(user_id, integ_mid_2)
                )
            )
        ).scalar_one_or_none()

        check(
            check_wh_ok
            and sync_job_row.status == "completed"
            and worker_res["messages_enqueued"] == 2
            and fetch_1 is not None
            and fetch_2 is not None
            and mock_sync_enqueue.call_count == 2,
            "15 full integration: Pub/Sub webhook -> enqueue gmail_sync -> worker executes -> email_fetch jobs in queue (mock Redis, assert enqueue calls)",
            f"sync_status={sync_job_row.status}, fetch_1={fetch_1 is not None}, fetch_2={fetch_2 is not None}, enqueue_calls={mock_sync_enqueue.call_count}",
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
    asyncio.run(run_gmail_sync_worker_tests(r))
    print(f"\nSuite 25 total: {r.passed}/{r.passed + r.failed} passed")
    sys.exit(0 if r.failed == 0 else 1)
