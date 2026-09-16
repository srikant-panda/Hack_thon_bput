"""RT-10 — Dead letter queue ops dashboard + retry/backoff tuning + poison message visibility tests (Suite 30).

Covers 12 checks:
1 list dead_letter jobs: 3 seeded → 3 returned, paginated.
2 filter by job_type: gmail_sync only → correct subset.
3 retry job: status → queued, retry_count reset, Redis enqueue called.
4 delete job: status → deleted, no longer in list.
5 stats endpoint: total=3, oldest_age_hours calculated, by_job_type breakdown.
6 RBAC: analyst cannot access DLQ routes (403); admin can.
7 RLS: admin sees all orgs' dead letters; non-admin sees only own (if applicable).
8 retry policy: GmailAuthError → immediate dead_letter (retry_count=0, max_retries=5, but status='dead_letter' on first failure).
9 retry policy: GmailRateLimitError → longer backoff delays (30s, 5min, 30min, 2h, 6h).
10 retry policy: MIMECorruptionError → immediate dead_letter.
11 detail endpoint: full payload + error + retry history returned.
12 manual retry audit: audit_logs row created with actor_type='user', action='manual_dlq_retry'.

Run standalone:
    uv run python scripts/test_dlq_ops.py
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
from sqlalchemy import delete, select

from app.core.retry_policy import (
    GmailAuthError,
    GmailRateLimitError,
    MIMECorruptionError,
    compute_retry_delay,
    evaluate_retry_policy,
)
from app.core.security import CurrentUser, get_current_user
from app.db.admin import _get_admin_session_maker
from app.db.models import AuditLog, JobQueue
from app.main import app
from app.services.job_state_service import update_job_status


async def run_dlq_ops_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("RT-10 DLQ Ops Dashboard, Retry Backoff & Poison Visibility (Suite 30)")
    print("-" * 60)

    admin_maker = _get_admin_session_maker()
    uid = uuid.uuid4().hex[:8]
    admin_id = f"usr_admin_{uid}"
    other_id = f"usr_other_{uid}"
    analyst_id = f"usr_analyst_{uid}"

    admin_user = CurrentUser(id=admin_id, email="admin@cyberguard.test", role="admin")
    other_user = CurrentUser(id=other_id, email="other@cyberguard.test", role="user")
    analyst_user = CurrentUser(id=analyst_id, email="analyst@cyberguard.test", role="analyst")

    # Clean up previous test jobs if any
    job1_id = f"job_dlq_test1_{uid}"
    job2_id = f"job_dlq_test2_{uid}"
    job3_id = f"job_dlq_test3_{uid}"
    test_job_ids = [job1_id, job2_id, job3_id]

    from app.db.models import AuditLog, JobQueue, User

    async with admin_maker() as session:
        await session.execute(delete(JobQueue).where(JobQueue.status == "dead_letter"))
        await session.execute(delete(JobQueue).where(JobQueue.job_id.in_(test_job_ids)))
        await session.execute(delete(AuditLog).where(AuditLog.user_id.in_([admin_id, other_id, analyst_id])))
        await session.execute(delete(User).where(User.id.in_([admin_id, other_id, analyst_id])))
        await session.commit()

        u_admin = User(id=admin_id, email=f"{admin_id}@cyberguard.test", username=admin_id, full_name="Admin User")
        u_other = User(id=other_id, email=f"{other_id}@cyberguard.test", username=other_id, full_name="Other User")
        u_analyst = User(id=analyst_id, email=f"{analyst_id}@cyberguard.test", username=analyst_id, full_name="Analyst User")
        session.add_all([u_admin, u_other, u_analyst])
        await session.flush()

        # Seed 3 dead_letter jobs
        now = datetime.now(timezone.utc)
        j1 = JobQueue(
            id=str(uuid.uuid4()),
            job_id=job1_id,
            job_type="gmail_sync",
            owner_user_id=admin_id,
            status="dead_letter",
            retry_count=0,
            max_retries=5,
            payload={"account_id": "acc_001", "correlation_id": f"corr_1_{uid}"},
            error="GmailAuthError: 401 Unauthorized",
            created_at=now - timedelta(hours=3),
            updated_at=now - timedelta(hours=3),
        )
        j2 = JobQueue(
            id=str(uuid.uuid4()),
            job_id=job2_id,
            job_type="email_fetch",
            owner_user_id=admin_id,
            status="dead_letter",
            retry_count=2,
            max_retries=5,
            payload={"message_id": "msg_002", "correlation_id": f"corr_2_{uid}"},
            error="MIMECorruptionError: Corrupt boundary delimiter",
            created_at=now - timedelta(hours=2),
            updated_at=now - timedelta(hours=2),
        )
        j3 = JobQueue(
            id=str(uuid.uuid4()),
            job_id=job3_id,
            job_type="email_analysis",
            owner_user_id=other_id,
            status="dead_letter",
            retry_count=5,
            max_retries=5,
            payload={"email_id": "em_003", "correlation_id": f"corr_3_{uid}"},
            error="GmailRateLimitError: 429 quota exceeded",
            created_at=now - timedelta(hours=6),
            updated_at=now - timedelta(hours=1),
        )
        session.add_all([j1, j2, j3])
        await session.commit()

    # Base test client with admin credentials
    app.dependency_overrides[get_current_user] = lambda: admin_user
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # -------------------------------------------------------------------
        # Check 1: list dead_letter jobs: 3 seeded → 3 returned, paginated
        # -------------------------------------------------------------------
        res1 = await client.get("/api/v1/dlq/jobs?limit=50&page=1")
        data1 = res1.json() if res1.status_code == 200 else {}
        returned_ids1 = [j["job_id"] for j in data1.get("jobs", [])]
        c1_ok = (
            res1.status_code == 200
            and data1.get("total", 0) >= 3
            and all(jid in returned_ids1 for jid in test_job_ids)
        )

        # Also test pagination limit=2
        res1_page = await client.get("/api/v1/dlq/jobs?limit=2&page=1")
        data1_page = res1_page.json() if res1_page.status_code == 200 else {}
        c1_ok = c1_ok and len(data1_page.get("jobs", [])) == 2

        check(
            c1_ok,
            "1 list dead_letter jobs: 3 seeded → 3 returned, paginated",
            f"status={res1.status_code}, total={data1.get('total')}, returned={returned_ids1}",
        )

        # -------------------------------------------------------------------
        # Check 2: filter by job_type: gmail_sync only → correct subset
        # -------------------------------------------------------------------
        res2 = await client.get("/api/v1/dlq/jobs?job_type=gmail_sync")
        data2 = res2.json() if res2.status_code == 200 else {}
        jobs2 = data2.get("jobs", [])
        c2_ok = (
            res2.status_code == 200
            and len(jobs2) >= 1
            and all(j["job_type"] == "gmail_sync" for j in jobs2)
            and any(j["job_id"] == job1_id for j in jobs2)
            and not any(j["job_id"] in (job2_id, job3_id) for j in jobs2)
        )
        check(
            c2_ok,
            "2 filter by job_type: gmail_sync only → correct subset",
            f"returned count={len(jobs2)}, types={[j['job_type'] for j in jobs2]}",
        )

        # -------------------------------------------------------------------
        # Check 3: retry job: status → queued, retry_count reset, Redis enqueue called
        # -------------------------------------------------------------------
        with patch("app.api.routes_dlq.enqueue", new_callable=AsyncMock) as mock_enqueue:
            mock_enqueue.return_value = "arq:job:123"
            res3 = await client.post(f"/api/v1/dlq/jobs/{job1_id}/retry")
            data3 = res3.json() if res3.status_code == 200 else {}

            # Verify in DB
            async with admin_maker() as session:
                q3 = await session.execute(select(JobQueue).where(JobQueue.job_id == job1_id))
                db_j1 = q3.scalar_one_or_none()

            c3_ok = (
                res3.status_code == 200
                and data3.get("status") == "queued"
                and db_j1 is not None
                and db_j1.status == "queued"
                and db_j1.retry_count == 0
                and mock_enqueue.called
            )
            check(
                c3_ok,
                "3 retry job: status → queued, retry_count reset, Redis enqueue called",
                f"status={res3.status_code}, db_status={getattr(db_j1, 'status', None)}, retry_count={getattr(db_j1, 'retry_count', None)}, enqueue_called={mock_enqueue.called}",
            )

        # -------------------------------------------------------------------
        # Check 4: delete job: status → deleted, no longer in list
        # -------------------------------------------------------------------
        res4 = await client.delete(f"/api/v1/dlq/jobs/{job2_id}")
        data4 = res4.json() if res4.status_code == 200 else {}

        # Verify in DB and via list endpoint
        async with admin_maker() as session:
            q4 = await session.execute(select(JobQueue).where(JobQueue.job_id == job2_id))
            db_j2 = q4.scalar_one_or_none()

        res4_list = await client.get("/api/v1/dlq/jobs")
        dlq_list_ids = [j["job_id"] for j in res4_list.json().get("jobs", [])]

        c4_ok = (
            res4.status_code == 200
            and data4.get("status") == "deleted"
            and db_j2 is not None
            and db_j2.status == "deleted"
            and job2_id not in dlq_list_ids
        )
        check(
            c4_ok,
            "4 delete job: status → deleted, no longer in list",
            f"status={res4.status_code}, db_status={getattr(db_j2, 'status', None)}, in_list={job2_id in dlq_list_ids}",
        )

        # -------------------------------------------------------------------
        # Check 5: stats endpoint: total=3, oldest_age_hours calculated, by_job_type breakdown
        # -------------------------------------------------------------------
        # Let's seed a clean set for exact stats verification: 3 dead_letter jobs
        stat_job_a = f"stat_job_a_{uid}"
        stat_job_b = f"stat_job_b_{uid}"
        stat_job_c = f"stat_job_c_{uid}"
        async with admin_maker() as session:
            await session.execute(
                delete(JobQueue).where(JobQueue.status == "dead_letter")
            )
            # Add 3 controlled dead-letter jobs
            t_now = datetime.now(timezone.utc)
            s_a = JobQueue(
                id=str(uuid.uuid4()),
                job_id=stat_job_a,
                job_type="gmail_sync",
                owner_user_id=admin_id,
                status="dead_letter",
                retry_count=1,
                payload={},
                created_at=t_now - timedelta(hours=4),
                updated_at=t_now - timedelta(hours=4),
            )
            s_b = JobQueue(
                id=str(uuid.uuid4()),
                job_id=stat_job_b,
                job_type="email_fetch",
                owner_user_id=admin_id,
                status="dead_letter",
                retry_count=2,
                payload={},
                created_at=t_now - timedelta(hours=2),
                updated_at=t_now - timedelta(hours=2),
            )
            s_c = JobQueue(
                id=str(uuid.uuid4()),
                job_id=stat_job_c,
                job_type="email_analysis",
                owner_user_id=other_id,
                status="dead_letter",
                retry_count=3,
                payload={"email_id": "em_003", "correlation_id": f"corr_3_{uid}"},
                error="GmailRateLimitError: 429 quota exceeded",
                created_at=t_now - timedelta(hours=6),
                updated_at=t_now - timedelta(hours=6),
            )
            session.add_all([s_a, s_b, s_c])
            await session.commit()

        res5 = await client.get("/api/v1/dlq/stats")
        data5 = res5.json() if res5.status_code == 200 else {}
        total_dl = data5.get("total_dead_letter", 0)
        by_type = data5.get("by_job_type", {})
        oldest_hrs = data5.get("oldest_age_hours", 0.0)

        c5_ok = (
            res5.status_code == 200
            and total_dl >= 3
            and oldest_hrs >= 5.8
            and by_type.get("gmail_sync", 0) >= 1
            and by_type.get("email_fetch", 0) >= 1
            and by_type.get("email_analysis", 0) >= 1
        )
        check(
            c5_ok,
            "5 stats endpoint: total=3, oldest_age_hours calculated, by_job_type breakdown",
            f"total={total_dl}, oldest_age_hours={oldest_hrs}, by_type={by_type}",
        )

        # -------------------------------------------------------------------
        # Check 6: RBAC: analyst cannot access DLQ routes (403); admin can
        # -------------------------------------------------------------------
        app.dependency_overrides[get_current_user] = lambda: analyst_user
        res6_analyst = await client.get("/api/v1/dlq/jobs")
        res6_analyst_retry = await client.post(f"/api/v1/dlq/jobs/{stat_job_a}/retry")

        app.dependency_overrides[get_current_user] = lambda: admin_user
        res6_admin = await client.get("/api/v1/dlq/jobs")

        c6_ok = (
            res6_analyst.status_code == 403
            and res6_analyst_retry.status_code == 403
            and res6_admin.status_code == 200
        )
        check(
            c6_ok,
            "6 RBAC: analyst cannot access DLQ routes (403); admin can",
            f"analyst_jobs={res6_analyst.status_code}, analyst_retry={res6_analyst_retry.status_code}, admin_jobs={res6_admin.status_code}",
        )

        # -------------------------------------------------------------------
        # Check 7: RLS: admin sees all orgs' dead letters; non-admin sees only own (if applicable)
        # -------------------------------------------------------------------
        # Admin requests list: sees jobs with admin_id and other_id
        res7_admin = await client.get("/api/v1/dlq/jobs?limit=50")
        admin_jobs = res7_admin.json().get("jobs", [])
        admin_seen_owners = {j["owner_user_id"] for j in admin_jobs}

        # Non-admin user requests list: sees only own jobs
        app.dependency_overrides[get_current_user] = lambda: other_user
        res7_member = await client.get("/api/v1/dlq/jobs?limit=50")
        member_jobs = res7_member.json().get("jobs", [])
        member_seen_owners = {j["owner_user_id"] for j in member_jobs}

        # Reset to admin
        app.dependency_overrides[get_current_user] = lambda: admin_user

        c7_ok = (
            res7_admin.status_code == 200
            and res7_member.status_code == 200
            and len(admin_seen_owners) >= 2
            and (len(member_seen_owners) == 0 or member_seen_owners == {other_id})
        )
        check(
            c7_ok,
            "7 RLS: admin sees all orgs' dead letters; non-admin sees only own (if applicable)",
            f"admin_owners={admin_seen_owners}, non_admin_owners={member_seen_owners}",
        )

    # -----------------------------------------------------------------------
    # Check 8: retry policy: GmailAuthError → immediate dead_letter (retry_count=0, max_retries=5, but status='dead_letter' on first failure)
    # -----------------------------------------------------------------------
    auth_err = GmailAuthError("401 Unauthorized: token revoked by user")
    policy_auth = evaluate_retry_policy(auth_err, current_retry=0, max_retries=5)

    # Also test via job_state_service update_job_status
    auth_job_id = f"job_auth_test_{uid}"
    async with admin_maker() as session:
        aj = JobQueue(
            id=str(uuid.uuid4()),
            job_id=auth_job_id,
            job_type="gmail_sync",
            owner_user_id=admin_id,
            status="queued",
            retry_count=0,
            max_retries=5,
            payload={},
        )
        session.add(aj)
        await session.commit()
        await update_job_status(session, auth_job_id, "failed", error=auth_err)

    async with admin_maker() as session:
        q_auth = await session.execute(select(JobQueue).where(JobQueue.job_id == auth_job_id))
        db_aj = q_auth.scalar_one_or_none()

    c8_ok = (
        policy_auth.should_retry is False
        and policy_auth.status == "dead_letter"
        and policy_auth.is_poison is True
        and db_aj is not None
        and db_aj.status == "dead_letter"
        and db_aj.retry_count == 0
    )
    check(
        c8_ok,
        "8 retry policy: GmailAuthError → immediate dead_letter (retry_count=0, max_retries=5, but status='dead_letter' on first failure)",
        f"should_retry={policy_auth.should_retry}, status={policy_auth.status}, db_status={getattr(db_aj, 'status', None)}, retry_count={getattr(db_aj, 'retry_count', None)}",
    )

    # -----------------------------------------------------------------------
    # Check 9: retry policy: GmailRateLimitError → longer backoff delays (30s, 5min, 30min, 2h, 6h)
    # -----------------------------------------------------------------------
    rl_err = GmailRateLimitError("429 Too Many Requests: Rate limit exceeded")
    expected_delays = [30, 300, 1800, 7200, 21600]
    actual_delays = [
        compute_retry_delay(r, error_category=rl_err, jitter=False) for r in range(1, 6)
    ]
    c9_ok = actual_delays == expected_delays
    check(
        c9_ok,
        "9 retry policy: GmailRateLimitError → longer backoff delays (30s, 5min, 30min, 2h, 6h)",
        f"actual={actual_delays}, expected={expected_delays}",
    )

    # -----------------------------------------------------------------------
    # Check 10: retry policy: MIMECorruptionError → immediate dead_letter
    # -----------------------------------------------------------------------
    mime_err = MIMECorruptionError("Corrupt MIME boundary delimiter")
    policy_mime = evaluate_retry_policy(mime_err, current_retry=0, max_retries=5)

    mime_job_id = f"job_mime_test_{uid}"
    async with admin_maker() as session:
        mj = JobQueue(
            id=str(uuid.uuid4()),
            job_id=mime_job_id,
            job_type="email_fetch",
            owner_user_id=admin_id,
            status="queued",
            retry_count=0,
            max_retries=5,
            payload={},
        )
        session.add(mj)
        await session.commit()
        await update_job_status(session, mime_job_id, "failed", error=mime_err)

    async with admin_maker() as session:
        q_mime = await session.execute(select(JobQueue).where(JobQueue.job_id == mime_job_id))
        db_mj = q_mime.scalar_one_or_none()

    c10_ok = (
        policy_mime.should_retry is False
        and policy_mime.status == "dead_letter"
        and policy_mime.is_poison is True
        and db_mj is not None
        and db_mj.status == "dead_letter"
        and db_mj.retry_count == 0
    )
    check(
        c10_ok,
        "10 retry policy: MIMECorruptionError → immediate dead_letter",
        f"should_retry={policy_mime.should_retry}, status={policy_mime.status}, db_status={getattr(db_mj, 'status', None)}",
    )

    # -----------------------------------------------------------------------
    # Check 11: detail endpoint: full payload + error + retry history returned
    # -----------------------------------------------------------------------
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res11 = await client.get(f"/api/v1/dlq/jobs/{stat_job_c}")
        data11 = res11.json() if res11.status_code == 200 else {}
        c11_ok = (
            res11.status_code == 200
            and data11.get("job_id") == stat_job_c
            and data11.get("payload", {}).get("email_id") == "em_003"
            and "429" in (data11.get("error") or "")
            and "retry_history" in data11
            and len(data11["retry_history"]) >= 1
        )
        check(
            c11_ok,
            "11 detail endpoint: full payload + error + retry history returned",
            f"status={res11.status_code}, job_id={data11.get('job_id')}, payload={data11.get('payload')}, history_len={len(data11.get('retry_history', []))}",
        )

        # -------------------------------------------------------------------
        # Check 12: manual retry audit: audit_logs row created with actor_type='user', action='manual_dlq_retry'
        # -------------------------------------------------------------------
        with patch("app.api.routes_dlq.enqueue", new_callable=AsyncMock):
            res12 = await client.post(f"/api/v1/dlq/jobs/{stat_job_c}/retry")

        async with admin_maker() as session:
            q12 = await session.execute(
                select(AuditLog)
                .where(
                    AuditLog.action == "manual_dlq_retry",
                    AuditLog.resource == f"job:{stat_job_c}",
                )
                .order_by(AuditLog.created_at.desc())
            )
            audit_entry = q12.scalar_one_or_none()

        c12_ok = (
            res12.status_code == 200
            and audit_entry is not None
            and audit_entry.actor_type == "user"
            and audit_entry.action == "manual_dlq_retry"
            and audit_entry.user_id == admin_id
        )
        check(
            c12_ok,
            "12 manual retry audit: audit_logs row created with actor_type='user', action='manual_dlq_retry'",
            f"res_status={res12.status_code}, audit_exists={audit_entry is not None}, actor_type={getattr(audit_entry, 'actor_type', None)}, action={getattr(audit_entry, 'action', None)}",
        )

    # Cleanup overrides
    app.dependency_overrides.pop(get_current_user, None)


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
        print(f"\nSuite 30 total: {self.passed}/{total} passed")
        return 0 if self.failed == 0 else 1


if __name__ == "__main__":
    runner = StandaloneRunner()
    asyncio.run(run_dlq_ops_tests(runner))
    sys.exit(runner.report())
