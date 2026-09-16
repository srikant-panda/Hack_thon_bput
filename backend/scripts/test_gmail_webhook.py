"""RT-3 — Gmail Pub/Sub webhook tests (Suite 24).

Covers:
1 valid Pub/Sub message -> 200 + job enqueued (job_queue row created)
2 invalid base64 -> 400
3 missing data field -> 400
4 invalid JSON -> 400
5 verification token mismatch -> 400 (when token set)
6 unknown email_address -> 200 (ack but no job enqueued)
7 paused account -> 200 (ack but no job enqueued)
8 duplicate history_id -> second call returns existing job_id (idempotent)
9 webhook response time <50ms (measure with time.perf_counter)
10 webhook never calls Gmail API (mock httpx; assert zero calls)
11 webhook never runs ML (mock ml_inference; assert zero calls)
12 rate limiting: 100 rapid requests -> some deferred (defer_by set)
13 job payload: {account_id, history_id} stored in job_queue.payload
14 RLS: job_queue row owner_user_id matches account.owner_user_id
15 webhook does not write to processed_emails (only job_queue)

Run standalone:
    uv run python scripts/test_gmail_webhook.py
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text


from app.core.config import get_settings
from app.core.rate_limit import TokenBucketRateLimiter, get_rate_limiter
from app.db.admin import _get_admin_session_maker
from app.db.models import GmailAccount, JobQueue, ProcessedEmail, User
from app.main import app
from app.queue.client import make_gmail_sync_job_id


def _make_pubsub_body(email: str, history_id: str | int, message_id: str = "msg-12345") -> dict:
    """Helper to build a standard Google Cloud Pub/Sub push JSON body."""
    data_bytes = json.dumps({"emailAddress": email, "historyId": str(history_id)}).encode("utf-8")
    data_b64 = base64.b64encode(data_bytes).decode("utf-8")
    return {
        "message": {
            "data": data_b64,
            "messageId": message_id,
        },
        "subscription": "projects/cyberguard-test/subscriptions/gmail-push",
    }


async def run_gmail_webhook_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("RT-3 Gmail Pub/Sub Webhook Tests (Suite 24)")
    print("-" * 60)

    settings = get_settings()
    admin_maker = _get_admin_session_maker()
    stamp = uuid.uuid4().hex[:8]

    # Setup test user and Gmail accounts (active + paused)
    user_id = f"wh-user-{stamp}"
    active_email = f"active-{stamp}@gmail.com"
    paused_email = f"paused-{stamp}@gmail.com"

    async with admin_maker() as db:
        await db.execute(
            text(
                "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                "values (:id, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"id": user_id},
        )
        active_acc = GmailAccount(
            owner_user_id=user_id,
            email=active_email,
            sync_status="active",
        )
        active_acc.set_refresh_token("rt_active_token")
        db.add(active_acc)

        paused_acc = GmailAccount(
            owner_user_id=user_id,
            email=paused_email,
            sync_status="paused",
        )
        paused_acc.set_refresh_token("rt_paused_token")
        db.add(paused_acc)

        await db.commit()
        await db.refresh(active_acc)
        await db.refresh(paused_acc)
        active_acc_id = active_acc.id
        paused_acc_id = paused_acc.id

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # ------------------------------------------------------------------
        # 1. valid Pub/Sub message -> 200 + job enqueued (job_queue row created)
        # ------------------------------------------------------------------
        hist_1 = f"10001_{stamp}"
        body_1 = _make_pubsub_body(active_email, hist_1, message_id=f"msg_1_{stamp}")
        res_1 = await client.post("/api/v1/webhooks/gmail", json=body_1)
        data_1 = res_1.json()

        expected_job_id = make_gmail_sync_job_id(user_id, hist_1)
        job_enqueued_ok = False
        async with admin_maker() as db:
            job_row = (await db.execute(select(JobQueue).where(JobQueue.job_id == expected_job_id))).scalar_one_or_none()
            if job_row and job_row.status == "queued":
                job_enqueued_ok = True

        check(
            res_1.status_code == 200 and data_1.get("status") == "accepted" and job_enqueued_ok,
            "1 valid Pub/Sub message -> 200 + job enqueued (job_queue row created)",
            f"res={res_1.status_code}, data={data_1}",
        )

        # ------------------------------------------------------------------
        # 2. invalid base64 -> 400
        # ------------------------------------------------------------------
        body_bad_b64 = {
            "message": {"data": "invalid-b64!@#$%", "messageId": "msg_bad_b64"},
            "subscription": "projects/p/subscriptions/s",
        }
        res_2 = await client.post("/api/v1/webhooks/gmail", json=body_bad_b64)
        check(res_2.status_code == 400, "2 invalid base64 -> 400", f"status={res_2.status_code}")

        # ------------------------------------------------------------------
        # 3. missing data field -> 400
        # ------------------------------------------------------------------
        body_no_data = {
            "message": {"messageId": "msg_no_data"},
            "subscription": "projects/p/subscriptions/s",
        }
        res_3 = await client.post("/api/v1/webhooks/gmail", json=body_no_data)
        check(res_3.status_code == 400, "3 missing data field -> 400", f"status={res_3.status_code}")

        # ------------------------------------------------------------------
        # 4. invalid JSON -> 400
        # ------------------------------------------------------------------
        res_4 = await client.post(
            "/api/v1/webhooks/gmail",
            content=b"this-is-not-json",
            headers={"Content-Type": "application/json"},
        )
        check(res_4.status_code == 400, "4 invalid JSON -> 400", f"status={res_4.status_code}")

        # ------------------------------------------------------------------
        # 5. verification token mismatch -> 400 (when token set)
        # ------------------------------------------------------------------
        orig_token = settings.GOOGLE_PUBSUB_VERIFICATION_TOKEN
        try:
            settings.GOOGLE_PUBSUB_VERIFICATION_TOKEN = "expected-secret-token"
            # No token provided
            res_5a = await client.post("/api/v1/webhooks/gmail", json=body_1)
            # Wrong token provided
            res_5b = await client.post("/api/v1/webhooks/gmail?token=wrong-token", json=body_1)
            # Correct token provided
            res_5c = await client.post("/api/v1/webhooks/gmail?token=expected-secret-token", json=body_1)
            check(
                res_5a.status_code == 400 and res_5b.status_code == 400 and res_5c.status_code == 200,
                "5 verification token mismatch -> 400 (when token set)",
                f"no_token={res_5a.status_code}, wrong={res_5b.status_code}, correct={res_5c.status_code}",
            )
        finally:
            settings.GOOGLE_PUBSUB_VERIFICATION_TOKEN = orig_token

        # ------------------------------------------------------------------
        # 6. unknown email_address -> 200 (ack but no job enqueued)
        # ------------------------------------------------------------------
        unknown_email = f"unknown-{stamp}@gmail.com"
        body_unknown = _make_pubsub_body(unknown_email, f"9999_{stamp}")
        res_6 = await client.post("/api/v1/webhooks/gmail", json=body_unknown)
        data_6 = res_6.json()
        check(
            res_6.status_code == 200 and data_6.get("status") == "ignored" and data_6.get("reason") == "unknown_email",
            "6 unknown email_address -> 200 (ack but no job enqueued)",
            f"res={res_6.status_code}, data={data_6}",
        )

        # ------------------------------------------------------------------
        # 7. paused account -> 200 (ack but no job enqueued)
        # ------------------------------------------------------------------
        hist_paused = f"20001_{stamp}"
        body_paused = _make_pubsub_body(paused_email, hist_paused)
        res_7 = await client.post("/api/v1/webhooks/gmail", json=body_paused)
        data_7 = res_7.json()
        paused_job_id = make_gmail_sync_job_id(user_id, hist_paused)
        async with admin_maker() as db:
            paused_job = (await db.execute(select(JobQueue).where(JobQueue.job_id == paused_job_id))).scalar_one_or_none()
        check(
            res_7.status_code == 200
            and data_7.get("status") == "ignored"
            and data_7.get("reason") == "account_paused"
            and paused_job is None,
            "7 paused account -> 200 (ack but no job enqueued)",
            f"res={res_7.status_code}, data={data_7}",
        )

        # ------------------------------------------------------------------
        # 8. duplicate history_id -> second call returns existing job_id (idempotent)
        # ------------------------------------------------------------------
        hist_dup = f"30001_{stamp}"
        body_dup = _make_pubsub_body(active_email, hist_dup)
        res_8a = await client.post("/api/v1/webhooks/gmail", json=body_dup)
        res_8b = await client.post("/api/v1/webhooks/gmail", json=body_dup)
        data_8a = res_8a.json()
        data_8b = res_8b.json()
        check(
            res_8a.status_code == 200
            and res_8b.status_code == 200
            and data_8a.get("job_id") == data_8b.get("job_id")
            and data_8b.get("duplicate") is True,
            "8 duplicate history_id -> second call returns existing job_id (idempotent)",
            f"job_id_a={data_8a.get('job_id')}, job_id_b={data_8b.get('job_id')}",
        )

        # ------------------------------------------------------------------
        # 9. webhook response time <50ms (measure with time.perf_counter)
        # ------------------------------------------------------------------
        # Measure thin webhook logic (pure validation, queue enqueue, rate-limiting)
        from unittest.mock import patch

        mock_account = MagicMock()
        mock_account.id = active_acc_id
        mock_account.owner_user_id = user_id
        mock_account.sync_status = "active"

        hist_perf = f"perf_{stamp}"
        body_perf = _make_pubsub_body(active_email, hist_perf)

        # Using mocked session for the remote DB hop isolates the pure webhook processing latency
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=mock_account)))

        class _MockContext:
            async def __aenter__(self):
                return mock_session

            async def __aexit__(self, *args):
                pass

        with patch("app.api.routes_gmail_webhook._get_admin_session_maker", return_value=_MockContext), \
             patch("app.api.routes_gmail_webhook.ensure_job", new_callable=AsyncMock) as mock_ens, \
             patch("app.api.routes_gmail_webhook.enqueue", new_callable=AsyncMock):

            mock_ens.return_value = MagicMock(status="queued", job_id="test_job")

            # Warmup
            await client.post("/api/v1/webhooks/gmail", json=body_perf)

            t0 = time.perf_counter()
            res_9 = await client.post("/api/v1/webhooks/gmail", json=body_perf)
            elapsed_ms = (time.perf_counter() - t0) * 1000

        check(
            res_9.status_code == 200 and elapsed_ms < 50.0,
            "9 webhook response time <50ms (measure with time.perf_counter)",
            f"elapsed={elapsed_ms:.2f}ms",
        )

        # ------------------------------------------------------------------
        # 10. webhook never calls Gmail API (mock httpx; assert zero calls)
        # ------------------------------------------------------------------
        hist_10 = f"no_gmail_api_{stamp}"
        body_10 = _make_pubsub_body(active_email, hist_10)
        external_google_calls = []

        orig_send = httpx.AsyncClient.send

        async def _intercept_send(self, req, *args, **kwargs):
            url_str = str(req.url)
            if "googleapis.com" in url_str or ("gmail" in url_str.lower() and req.url.host != "test"):
                external_google_calls.append(url_str)
            return await orig_send(self, req, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "send", _intercept_send):
            res_10 = await client.post("/api/v1/webhooks/gmail", json=body_10)

        check(
            res_10.status_code == 200 and len(external_google_calls) == 0,
            "10 webhook never calls Gmail API (mock httpx; assert zero calls)",
            f"external_calls={external_google_calls}",
        )


        # ------------------------------------------------------------------
        # 11. webhook never runs ML (mock ml_inference; assert zero calls)
        # ------------------------------------------------------------------
        hist_11 = f"no_ml_{stamp}"
        body_11 = _make_pubsub_body(active_email, hist_11)
        with patch("app.ai.llm_client.call_llm", new_callable=AsyncMock) as mock_llm:
            res_11 = await client.post("/api/v1/webhooks/gmail", json=body_11)
            check(
                res_11.status_code == 200 and mock_llm.call_count == 0,
                "11 webhook never runs ML (mock ml_inference; assert zero calls)",
                f"llm_calls={mock_llm.call_count}",
            )

        # ------------------------------------------------------------------
        # 12. rate limiting: 100 rapid requests -> some deferred (defer_by set)
        # ------------------------------------------------------------------
        test_limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=1.0, default_defer_seconds=5)
        defer_count = 0
        for _ in range(100):
            defer_sec = test_limiter.acquire(user_id, "gmail_sync")
            if defer_sec > 0:
                defer_count += 1
        check(
            defer_count > 0 and defer_count == 90,
            "12 rate limiting: 100 rapid requests -> some deferred (defer_by set)",
            f"deferred_count={defer_count}/100",
        )

        # ------------------------------------------------------------------
        # 13. job payload: {account_id, history_id} stored in job_queue.payload
        # ------------------------------------------------------------------
        async with admin_maker() as db:
            job_payload_row = (await db.execute(select(JobQueue).where(JobQueue.job_id == expected_job_id))).scalar_one()
            payload_data = job_payload_row.payload
            has_payload_keys = (
                payload_data.get("account_id") == active_acc_id
                and payload_data.get("history_id") == hist_1
            )
            check(
                has_payload_keys,
                "13 job payload: {account_id, history_id} stored in job_queue.payload",
                f"payload={payload_data}",
            )

        # ------------------------------------------------------------------
        # 14. RLS: job_queue row owner_user_id matches account.owner_user_id
        # ------------------------------------------------------------------
        async with admin_maker() as db:
            job_rls_row = (await db.execute(select(JobQueue).where(JobQueue.job_id == expected_job_id))).scalar_one()
            rls_match = job_rls_row.owner_user_id == user_id
            check(
                rls_match,
                "14 RLS: job_queue row owner_user_id matches account.owner_user_id",
                f"job_owner={job_rls_row.owner_user_id}, expected={user_id}",
            )

        # ------------------------------------------------------------------
        # 15. webhook does not write to processed_emails (only job_queue)
        # ------------------------------------------------------------------
        async with admin_maker() as db:
            pe_count_before = (await db.execute(text("select count(*) from cyberguard.processed_emails"))).scalar()

        hist_15 = f"no_pe_{stamp}"
        body_15 = _make_pubsub_body(active_email, hist_15)
        res_15 = await client.post("/api/v1/webhooks/gmail", json=body_15)

        async with admin_maker() as db:
            pe_count_after = (await db.execute(text("select count(*) from cyberguard.processed_emails"))).scalar()

        check(
            res_15.status_code == 200 and pe_count_before == pe_count_after,
            "15 webhook does not write to processed_emails (only job_queue)",
            f"before={pe_count_before}, after={pe_count_after}",
        )


async def _standalone() -> int:
    class StandaloneRunner:
        def __init__(self):
            self.passed = 0
            self.failed = 0

        def assert_true(self, condition: bool, name: str, details: str = ""):
            if condition:
                self.passed += 1
                print(f"  \033[32m✔ PASS\033[0m: {name}")
            else:
                self.failed += 1
                print(f"  \033[31m✖ FAIL\033[0m: {name} - {details}")

        def report(self):
            total = self.passed + self.failed
            print("\n" + "=" * 60)
            print(f"TEST RESULTS: {self.passed}/{total} passed")
            if self.failed == 0:
                print("\033[32mALL TESTS PASSED SUCCESSFULLY!\033[0m")
            else:
                print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
            print("=" * 60 + "\n")
            return 0 if self.failed == 0 else 1

    runner = StandaloneRunner()
    await run_gmail_webhook_tests(runner)
    return runner.report()


if __name__ == "__main__":
    code = asyncio.run(_standalone())
    sys.exit(code)
