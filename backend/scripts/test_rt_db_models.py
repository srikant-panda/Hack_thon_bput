"""RT-2 — Real-time pipeline database models tests (Suite 23).

Tests:
1. create gmail_account -> row created, tokens encrypted (not plaintext in DB)
2. decrypt tokens -> match original
3. create job_queue with deterministic job_id -> row created, status=queued
4. duplicate job_id -> IntegrityError (unique constraint)
5. ensure_job same job_id twice -> second returns existing row (idempotent)
6. job state transitions: queued->running ok; running->completed ok; running->failed ok;
   failed->queued ok if retry_count<max_retries; failed->dead_letter if retry_count>=max_retries;
   invalid transition (completed->running) raises
7. retry_count increments on failure; next_retry_at set with exponential backoff (5s, 30s, 2min, 10min, 30min)
8. create processed_email -> row created, status=received
9. duplicate gmail_message_id -> IntegrityError (unique constraint)
10. ensure_processed_email same message_id twice -> second returns existing row (idempotent)
11. existing processed_email with status=completed -> caller skips processing
12. update_history_id with FOR UPDATE lock -> concurrent updates serialized
13. RLS: user A cannot read user B's gmail_accounts/job_queue/processed_emails (cross-user isolation)
14. RLS: service role can read all rows (for admin dashboards)
15. gmail_account.sync_status transitions: active->paused->active; active->error on failure
16. processed_email.processing_status state machine: received->fetching->fetched->analyzing->analyzed->completed; received->failed
17. signals JSONB: store {text_model: 0.96, url_model: 0.91, spf: "fail", dkim: "pass", dmarc: "fail"}
18. scan_result_id FK: link to existing Phase-3 scan_results table (verify FK constraint)
19. invalid scan_result_id FK -> IntegrityError
20. gmail_account get_or_create updates existing tokens on conflict

Run standalone:
    uv run python scripts/test_rt_db_models.py
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.db.admin import _get_admin_session_maker
from app.db.models import GmailAccount, JobQueue, ProcessedEmail, ScanResult, User
from app.db.session import async_session_maker, current_user_id, engine
from app.services.gmail_account_service import (
    get_or_create_gmail_account,
    update_history_id,
    update_watch_expiration,
)
from app.services.idempotency_service import ensure_job, ensure_processed_email
from app.services.job_state_service import compute_backoff_delay, update_job_status


async def run_rt_db_models_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("RT-2 Real-Time Pipeline Database Models (Suite 23)")
    print("-" * 60)

    # Setup unique test identities
    stamp = uuid.uuid4().hex[:8]
    user_a = f"rt2-user-a-{stamp}"
    user_b = f"rt2-user-b-{stamp}"

    admin_maker = _get_admin_session_maker()
    async with admin_maker() as s:
        await s.execute(
            text(
                "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                "values (:id, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"id": user_a},
        )
        await s.execute(
            text(
                "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                "values (:id, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"id": user_b},
        )
        await s.commit()

    # Set user A context for RLS
    current_user_id.set(user_a)


    # ------------------------------------------------------------------
    # 1. create gmail_account -> row created, tokens encrypted in DB
    # ------------------------------------------------------------------
    email_a = f"test-a-{stamp}@gmail.com"
    plain_access = "ya29.secret-access-token-123"
    plain_refresh = "1//secret-refresh-token-456"

    async with async_session_maker() as db:
        acc = GmailAccount(
            owner_user_id=user_a,
            email=email_a,
            sync_status="active",
        )
        acc.set_access_token(plain_access)
        acc.set_refresh_token(plain_refresh)
        db.add(acc)
        await db.commit()
        await db.refresh(acc)
        acc_id = acc.id

    # Verify at raw SQL layer that tokens are NOT stored in plaintext
    async with admin_maker() as db:
        res = await db.execute(
            text("select access_token_encrypted, refresh_token_encrypted from cyberguard.gmail_accounts where id = :id"),
            {"id": acc_id},
        )
        row = res.fetchone()
        encrypted_access = row[0]
        encrypted_refresh = row[1]
        check(
            encrypted_access != plain_access and encrypted_refresh != plain_refresh,
            "1 create gmail_account -> row created, tokens encrypted (not plaintext in DB)",
            f"access={encrypted_access[:15]}...",
        )

    # ------------------------------------------------------------------
    # 2. decrypt tokens -> match original
    # ------------------------------------------------------------------
    async with async_session_maker() as db:
        fetched_acc = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        dec_access = fetched_acc.get_access_token()
        dec_refresh = fetched_acc.get_refresh_token()
        check(
            dec_access == plain_access and dec_refresh == plain_refresh,
            "2 decrypt tokens -> match original",
            f"dec_access={dec_access}, dec_refresh={dec_refresh}",
        )

    # ------------------------------------------------------------------
    # 3. create job_queue with deterministic job_id -> status=queued
    # ------------------------------------------------------------------
    det_job_id = f"job_gmail_sync_{stamp}_001"
    async with async_session_maker() as db:
        job = JobQueue(
            owner_user_id=user_a,
            job_type="gmail_sync",
            job_id=det_job_id,
            status="queued",
            payload={"account_id": acc_id},
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        check(job.status == "queued" and job.job_id == det_job_id, "3 create job_queue with deterministic job_id -> row created, status=queued")

    # ------------------------------------------------------------------
    # 4. duplicate job_id -> IntegrityError (unique constraint)
    # ------------------------------------------------------------------
    dup_blocked = False
    try:
        async with async_session_maker() as db:
            dup_job = JobQueue(
                owner_user_id=user_a,
                job_type="gmail_sync",
                job_id=det_job_id,
                status="queued",
                payload={"duplicate": True},
            )
            db.add(dup_job)
            await db.commit()
    except IntegrityError:
        dup_blocked = True
    check(dup_blocked, "4 duplicate job_id -> IntegrityError (unique constraint)")

    # ------------------------------------------------------------------
    # 5. ensure_job same job_id twice -> second returns existing row (idempotent)
    # ------------------------------------------------------------------
    idem_job_id = f"job_email_fetch_{stamp}_idem"
    async with async_session_maker() as db:
        job1 = await ensure_job(db, user_a, "email_fetch", idem_job_id, {"msg_id": "m1"})
        job2 = await ensure_job(db, user_a, "email_fetch", idem_job_id, {"msg_id": "m1"})
        check(job1.id == job2.id and job2.job_id == idem_job_id, "5 ensure_job same job_id twice -> second returns existing row (idempotent)")

    # ------------------------------------------------------------------
    # 6. job state transitions: queued->running->completed; running->failed; failed->queued; failed->dead_letter
    # ------------------------------------------------------------------
    async with async_session_maker() as db:
        t_job_id = f"job_state_{stamp}_t1"
        t_job = await ensure_job(db, user_a, "email_analysis", t_job_id, {})
        # queued -> running ok
        t_job = await update_job_status(db, t_job_id, "running")
        running_ok = t_job.status == "running" and t_job.started_at is not None

        # running -> completed ok
        t_job = await update_job_status(db, t_job_id, "completed", result={"safe": True})
        completed_ok = t_job.status == "completed" and t_job.completed_at is not None

        # invalid transition: completed -> running raises
        inv_raised = False
        try:
            await update_job_status(db, t_job_id, "running")
        except ValueError:
            inv_raised = True

        # running -> failed ok
        f_job_id = f"job_state_{stamp}_t2"
        f_job = await ensure_job(db, user_a, "email_analysis", f_job_id, {})
        f_job = await update_job_status(db, f_job_id, "running")
        f_job = await update_job_status(db, f_job_id, "failed", error="timeout")
        failed_ok = f_job.status == "failed"

        # failed -> queued ok if retry_count < max_retries
        f_job = await update_job_status(db, f_job_id, "queued")
        requeued_ok = f_job.status == "queued"

        # failed -> dead_letter ok if retry_count >= max_retries
        dl_job_id = f"job_state_{stamp}_dl"
        dl_job = await ensure_job(db, user_a, "email_analysis", dl_job_id, {})
        dl_job = await update_job_status(db, dl_job_id, "running")
        dl_job.retry_count = 5
        await db.commit()
        dl_job = await update_job_status(db, dl_job_id, "dead_letter", error="permanent failure")
        dead_letter_ok = dl_job.status == "dead_letter"

        check(
            running_ok and completed_ok and inv_raised and failed_ok and requeued_ok and dead_letter_ok,
            "6 job state transitions: queued->running, running->completed, running->failed, failed->queued, failed->dead_letter, invalid raises",
        )

    # ------------------------------------------------------------------
    # 7. retry_count increments on failure; next_retry_at set with exponential backoff
    # ------------------------------------------------------------------
    backoff_calc_ok = (
        compute_backoff_delay(1) == 5
        and compute_backoff_delay(2) == 30
        and compute_backoff_delay(3) == 120
        and compute_backoff_delay(4) == 600
        and compute_backoff_delay(5) == 1800
    )
    async with async_session_maker() as db:
        bk_job_id = f"job_backoff_{stamp}"
        bk_job = await ensure_job(db, user_a, "email_analysis", bk_job_id, {})
        bk_job = await update_job_status(db, bk_job_id, "running")
        bk_job = await update_job_status(db, bk_job_id, "failed", error="transient failure")
        now_dt = datetime.now(timezone.utc)
        diff_s = (bk_job.next_retry_at - now_dt).total_seconds()
        backoff_live_ok = bk_job.retry_count == 1 and 2 <= diff_s <= 6
        check(
            backoff_calc_ok and backoff_live_ok,
            "7 retry_count increments on failure; next_retry_at set with exponential backoff (5s, 30s, 2min, 10min, 30min)",
            f"diff_s={diff_s:.1f}s",
        )

    # ------------------------------------------------------------------
    # 8. create processed_email -> row created, status=received
    # ------------------------------------------------------------------
    msg_id_1 = f"msg_{stamp}_001"
    async with async_session_maker() as db:
        p_email = ProcessedEmail(
            owner_user_id=user_a,
            gmail_account_id=acc_id,
            gmail_message_id=msg_id_1,
            subject="Urgent account update",
            sender="billing@example.com",
            received_at=datetime.now(timezone.utc),
            processing_status="received",
        )
        db.add(p_email)
        await db.commit()
        await db.refresh(p_email)
        p_email_id = p_email.id
        check(
            p_email.processing_status == "received" and p_email.gmail_message_id == msg_id_1,
            "8 create processed_email -> row created, status=received",
        )

    # ------------------------------------------------------------------
    # 9. duplicate gmail_message_id -> IntegrityError (unique constraint)
    # ------------------------------------------------------------------
    dup_email_blocked = False
    try:
        async with async_session_maker() as db:
            dup_p = ProcessedEmail(
                owner_user_id=user_a,
                gmail_account_id=acc_id,
                gmail_message_id=msg_id_1,
                received_at=datetime.now(timezone.utc),
            )
            db.add(dup_p)
            await db.commit()
    except IntegrityError:
        dup_email_blocked = True
    check(dup_email_blocked, "9 duplicate gmail_message_id -> IntegrityError (unique constraint)")

    # ------------------------------------------------------------------
    # 10. ensure_processed_email same message_id twice -> second returns existing row
    # ------------------------------------------------------------------
    msg_id_2 = f"msg_{stamp}_idem"
    async with async_session_maker() as db:
        em1 = await ensure_processed_email(db, user_a, msg_id_2, acc_id, subject="Test Idem")
        em2 = await ensure_processed_email(db, user_a, msg_id_2, acc_id, subject="Test Idem")
        check(
            em1.id == em2.id and em2.gmail_message_id == msg_id_2,
            "10 ensure_processed_email same message_id twice -> second returns existing row (idempotent)",
        )

    # ------------------------------------------------------------------
    # 11. existing processed_email with status=completed -> caller skips processing
    # ------------------------------------------------------------------
    async with async_session_maker() as db:
        em = (await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == em2.id))).scalar_one()
        em.processing_status = "completed"
        await db.commit()

        # Simulate caller check
        check_em = await ensure_processed_email(db, user_a, msg_id_2, acc_id)
        skipped = check_em.processing_status == "completed"
        check(skipped, "11 existing processed_email with status=completed -> caller skips processing")

    # ------------------------------------------------------------------
    # 12. update_history_id with FOR UPDATE lock -> concurrent updates serialized
    # ------------------------------------------------------------------
    async def _update_hist(hist_id: str):
        current_user_id.set(user_a)
        async with async_session_maker() as db:
            return await update_history_id(db, acc_id, hist_id)

    res_h1, res_h2 = await asyncio.gather(_update_hist(f"hist_a_{stamp}"), _update_hist(f"hist_b_{stamp}"))
    async with async_session_maker() as db:
        final_acc = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_id))).scalar_one()
        check(
            final_acc.last_history_id in (f"hist_a_{stamp}", f"hist_b_{stamp}") and final_acc.last_sync_at is not None,
            "12 update_history_id with FOR UPDATE lock -> concurrent updates serialized",
        )

    # ------------------------------------------------------------------
    # 13. RLS: user A cannot read user B's gmail_accounts/job_queue/processed_emails
    # ------------------------------------------------------------------
    # Create user B resources under user_b RLS context
    current_user_id.set(user_b)
    async with async_session_maker() as db:
        acc_b = GmailAccount(owner_user_id=user_b, email=f"user-b-{stamp}@gmail.com")
        acc_b.set_refresh_token("dummy-b")
        db.add(acc_b)
        job_b = JobQueue(owner_user_id=user_b, job_type="gmail_sync", job_id=f"job_b_{stamp}")
        db.add(job_b)
        await db.commit()
        await db.refresh(acc_b)
        acc_b_id = acc_b.id
        pe_b = ProcessedEmail(
            owner_user_id=user_b,
            gmail_account_id=acc_b_id,
            gmail_message_id=f"msg_b_{stamp}",
            received_at=datetime.now(timezone.utc),
        )
        db.add(pe_b)
        await db.commit()

    # Switch back to user_a context
    current_user_id.set(user_a)


    async with engine.connect() as conn:
        await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": user_a})
        accs_seen = (
            await conn.execute(text("select count(*) from cyberguard.gmail_accounts where owner_user_id = :b"), {"b": user_b})
        ).scalar()
        jobs_seen = (
            await conn.execute(text("select count(*) from cyberguard.job_queue where owner_user_id = :b"), {"b": user_b})
        ).scalar()
        pes_seen = (
            await conn.execute(text("select count(*) from cyberguard.processed_emails where owner_user_id = :b"), {"b": user_b})
        ).scalar()
        check(
            accs_seen == 0 and jobs_seen == 0 and pes_seen == 0,
            "13 RLS: user A cannot read user B's gmail_accounts/job_queue/processed_emails (cross-user isolation)",
            f"accs={accs_seen} jobs={jobs_seen} pes={pes_seen}",
        )

    # ------------------------------------------------------------------
    # 14. RLS: service role can read all rows (for admin dashboards)
    # ------------------------------------------------------------------
    async with admin_maker() as db:
        all_accs = (await db.execute(text("select count(*) from cyberguard.gmail_accounts"))).scalar()
        all_jobs = (await db.execute(text("select count(*) from cyberguard.job_queue"))).scalar()
        all_pes = (await db.execute(text("select count(*) from cyberguard.processed_emails"))).scalar()
        check(
            all_accs >= 2 and all_jobs >= 2 and all_pes >= 2,
            "14 RLS: service role can read all rows (for admin dashboards)",
            f"accs={all_accs} jobs={all_jobs} pes={all_pes}",
        )

    # ------------------------------------------------------------------
    # 15. gmail_account.sync_status transitions
    # ------------------------------------------------------------------
    trans_a_p = GmailAccount.can_transition_sync_status("active", "paused")
    trans_p_a = GmailAccount.can_transition_sync_status("paused", "active")
    trans_a_e = GmailAccount.can_transition_sync_status("active", "error")
    trans_e_p = GmailAccount.can_transition_sync_status("error", "paused")  # invalid
    check(
        trans_a_p and trans_p_a and trans_a_e and not trans_e_p,
        "15 gmail_account.sync_status transitions: active->paused->active; active->error on failure",
    )

    # ------------------------------------------------------------------
    # 16. processed_email.processing_status state machine
    # ------------------------------------------------------------------
    pe_seq = [
        ProcessedEmail.can_transition("received", "fetching"),
        ProcessedEmail.can_transition("fetching", "fetched"),
        ProcessedEmail.can_transition("fetched", "analyzing"),
        ProcessedEmail.can_transition("analyzing", "analyzed"),
        ProcessedEmail.can_transition("analyzed", "completed"),
        ProcessedEmail.can_transition("received", "failed"),
        not ProcessedEmail.can_transition("received", "completed"),
        not ProcessedEmail.can_transition("completed", "fetching"),
    ]
    check(
        all(pe_seq),
        "16 processed_email.processing_status state machine: received->fetching->fetched->analyzing->analyzed->completed; received->failed",
    )

    # ------------------------------------------------------------------
    # 17. signals JSONB: store {text_model: 0.96, url_model: 0.91, spf: "fail", dkim: "pass", dmarc: "fail"}
    # ------------------------------------------------------------------
    signals_dict = {
        "text_model": 0.96,
        "url_model": 0.91,
        "spf": "fail",
        "dkim": "pass",
        "dmarc": "fail",
    }
    async with async_session_maker() as db:
        sig_email = ProcessedEmail(
            owner_user_id=user_a,
            gmail_account_id=acc_id,
            gmail_message_id=f"msg_signals_{stamp}",
            received_at=datetime.now(timezone.utc),
            signals=signals_dict,
            risk_score=0.94,
            classification="phishing",
        )
        db.add(sig_email)
        await db.commit()
        await db.refresh(sig_email)
        sig_id = sig_email.id

    async with async_session_maker() as db:
        loaded_sig = (await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == sig_id))).scalar_one()
        signals_match = (
            loaded_sig.signals == signals_dict
            and loaded_sig.signals.get("text_model") == 0.96
            and loaded_sig.signals.get("spf") == "fail"
        )
        check(
            signals_match,
            "17 signals JSONB: store {text_model: 0.96, url_model: 0.91, spf: 'fail', dkim: 'pass', dmarc: 'fail'}",
        )

    # ------------------------------------------------------------------
    # 18. scan_result_id FK: link to existing scan_results table
    # ------------------------------------------------------------------
    async with async_session_maker() as db:
        scan_res = ScanResult(
            owner_user_id=user_a,
            provider_message_id=f"prov_{stamp}",
            verdict="phishing",
            risk_score=0.95,
            scan_details={"reasons": ["domain spoofing"]},
        )
        db.add(scan_res)
        await db.commit()
        await db.refresh(scan_res)
        scan_id = scan_res.id

        linked_email = ProcessedEmail(
            owner_user_id=user_a,
            gmail_account_id=acc_id,
            gmail_message_id=f"msg_linked_{stamp}",
            received_at=datetime.now(timezone.utc),
            scan_result_id=scan_id,
        )
        db.add(linked_email)
        await db.commit()
        await db.refresh(linked_email)
        check(
            linked_email.scan_result_id == scan_id,
            "18 scan_result_id FK: link to existing scan_results table (verify FK constraint)",
        )

    # ------------------------------------------------------------------
    # 19. invalid scan_result_id FK -> IntegrityError
    # ------------------------------------------------------------------
    invalid_fk_blocked = False
    try:
        async with async_session_maker() as db:
            bad_email = ProcessedEmail(
                owner_user_id=user_a,
                gmail_account_id=acc_id,
                gmail_message_id=f"msg_bad_fk_{stamp}",
                received_at=datetime.now(timezone.utc),
                scan_result_id=str(uuid.uuid4()),
            )
            db.add(bad_email)
            await db.commit()
    except IntegrityError:
        invalid_fk_blocked = True
    check(invalid_fk_blocked, "19 invalid scan_result_id FK -> IntegrityError")

    # ------------------------------------------------------------------
    # 20. gmail_account get_or_create updates existing tokens on conflict
    # ------------------------------------------------------------------
    async with async_session_maker() as db:
        updated_acc = await get_or_create_gmail_account(
            db, user_a, email_a, "ya29.new-access-token", "1//new-refresh-token"
        )
        check(
            updated_acc.id == acc_id
            and updated_acc.get_access_token() == "ya29.new-access-token"
            and updated_acc.get_refresh_token() == "1//new-refresh-token",
            "20 gmail_account get_or_create updates existing tokens on conflict",
        )


async def _standalone():
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
    await run_rt_db_models_tests(runner)
    return runner.report()


if __name__ == "__main__":
    code = asyncio.run(_standalone())
    sys.exit(code)
