"""RT-1 Real-time pipeline infrastructure tests (Redis + Arq + Docker + workers).

Suite 22 covering:
1. Redis connection via create_redis_pool() succeeds
2. Arq queue creation with ARQ_QUEUE_NAME
3. Enqueue job -> job_info returns pending status
4. Deterministic job ID: enqueue same job_id twice -> second returns existing job (idempotent)
5. Deterministic job ID convention helpers (gmail_sync and email_scan)
6. Worker settings: max_jobs matches config
7. Worker settings: job_timeout matches config
8. Worker skeletons inherit base settings and share config
9. Health /health -> 200 with status ok
10. Health /ready returns 200 when Postgres and Redis are healthy
11. Health /ready with Redis down -> 503
12. Health /ready with Postgres down -> 503
13. Worker context helper get_db_session yields valid session
14. Worker graceful shutdown: lifecycle hooks execute cleanly
15. Docker compose validation: docker-compose config exits 0
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from arq.jobs import JobStatus
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import OperationalError

from app.core.config import get_settings
from app.main import app
from app.queue.client import (
    QueueClient,
    close_redis_pool,
    create_redis_pool,
    enqueue,
    get_queue,
    make_email_scan_job_id,
    make_gmail_sync_job_id,
)
from app.workers.base import (
    WorkerSettings as BaseWorkerSettings,
    base_shutdown,
    base_startup,
    get_db_session,
    get_worker_logger,
)
from app.workers.email_worker import WorkerSettings as EmailWorkerSettings
from app.workers.gmail_worker import WorkerSettings as GmailWorkerSettings


class TestRunner:
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

    def skip(self, name: str, reason: str = ""):
        print(f"  \033[33m⊘ SKIP\033[0m: {name} ({reason})")

    def report(self):
        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"TEST RESULTS: {self.passed}/{total} passed")
        return 0 if self.failed == 0 else 1


async def run_rt_infrastructure_tests(runner: TestRunner):
    settings = get_settings()

    # -------------------------------------------------------------------------
    # 1. Redis connection via create_redis_pool() succeeds
    # -------------------------------------------------------------------------
    pool = None
    try:
        pool = await create_redis_pool()
        pong = await pool.ping()
        runner.assert_true(pong is True, "Redis connection via create_redis_pool() succeeds")
    except Exception as exc:
        runner.assert_true(False, "Redis connection via create_redis_pool() succeeds", str(exc))

    # -------------------------------------------------------------------------
    # 2. Arq queue creation with ARQ_QUEUE_NAME
    # -------------------------------------------------------------------------
    try:
        runner.assert_true(
            pool is not None and pool.default_queue_name == settings.ARQ_QUEUE_NAME,
            "Arq queue creation with ARQ_QUEUE_NAME",
            f"Expected {settings.ARQ_QUEUE_NAME}, got {getattr(pool, 'default_queue_name', None)}",
        )
    except Exception as exc:
        runner.assert_true(False, "Arq queue creation with ARQ_QUEUE_NAME", str(exc))

    # -------------------------------------------------------------------------
    # 3. Enqueue job -> job_info returns pending status
    # -------------------------------------------------------------------------
    try:
        queue = QueueClient(pool)
        test_job_id = f"test_job_{uuid.uuid4().hex[:8]}"
        enqueued = await queue.enqueue_job("sample_task", key="value", _job_id=test_job_id)
        status = await enqueued.status() if enqueued else None
        info = await queue.job_info(test_job_id)
        runner.assert_true(
            enqueued is not None and status == JobStatus.queued and info is not None,
            "Enqueue job -> job_info returns pending status",
            f"status={status}, info={info}",
        )
    except Exception as exc:
        runner.assert_true(False, "Enqueue job -> job_info returns pending status", str(exc))

    # -------------------------------------------------------------------------
    # 4. Deterministic job ID: enqueue same job_id twice -> second returns existing job (idempotent)
    # -------------------------------------------------------------------------
    try:
        queue = QueueClient(pool)
        det_id = f"sync:user_{uuid.uuid4().hex[:6]}:101"
        job1 = await queue.enqueue_job("sync_action", _job_id=det_id)
        job2 = await queue.enqueue_job("sync_action", _job_id=det_id)
        runner.assert_true(
            job1 is not None and job2 is not None and job2.job_id == det_id,
            "Deterministic job ID: enqueue same job_id twice returns existing job",
            f"job1={job1}, job2={job2}",
        )
    except Exception as exc:
        runner.assert_true(
            False,
            "Deterministic job ID: enqueue same job_id twice returns existing job",
            str(exc),
        )

    # -------------------------------------------------------------------------
    # 5. Deterministic job ID convention helpers
    # -------------------------------------------------------------------------
    try:
        uid = "u-soc-42"
        hid = "hist-999"
        mid = "msg-123"
        gid = make_gmail_sync_job_id(uid, hid)
        eid = make_email_scan_job_id(uid, mid)
        runner.assert_true(
            gid == f"gmail_sync:{uid}:{hid}" and eid == f"email_scan:{uid}:{mid}",
            "Deterministic job ID conventions format correctly",
            f"gid={gid}, eid={eid}",
        )
    except Exception as exc:
        runner.assert_true(False, "Deterministic job ID conventions format correctly", str(exc))

    # -------------------------------------------------------------------------
    # 6. Worker settings: max_jobs matches config
    # -------------------------------------------------------------------------
    runner.assert_true(
        BaseWorkerSettings.max_jobs == settings.ARQ_MAX_JOBS,
        "Worker settings: max_jobs matches config",
        f"Expected {settings.ARQ_MAX_JOBS}, got {BaseWorkerSettings.max_jobs}",
    )

    # -------------------------------------------------------------------------
    # 7. Worker settings: job_timeout matches config
    # -------------------------------------------------------------------------
    runner.assert_true(
        BaseWorkerSettings.job_timeout == settings.ARQ_JOB_TIMEOUT,
        "Worker settings: job_timeout matches config",
        f"Expected {settings.ARQ_JOB_TIMEOUT}, got {BaseWorkerSettings.job_timeout}",
    )

    # -------------------------------------------------------------------------
    # 8. Worker skeletons inherit base settings and share config
    # -------------------------------------------------------------------------
    try:
        both_inherit = issubclass(GmailWorkerSettings, BaseWorkerSettings) and issubclass(
            EmailWorkerSettings, BaseWorkerSettings
        )
        empty_functions = GmailWorkerSettings.functions == [] and EmailWorkerSettings.functions == []
        retries_ok = GmailWorkerSettings.retry_jobs is True and GmailWorkerSettings.max_tries == 3
        runner.assert_true(
            both_inherit and empty_functions and retries_ok,
            "Worker skeletons inherit base settings and share config",
            f"inherit={both_inherit}, empty={empty_functions}, retries={retries_ok}",
        )
    except Exception as exc:
        runner.assert_true(False, "Worker skeletons inherit base settings and share config", str(exc))

    # -------------------------------------------------------------------------
    # 9. Health /health -> 200 with status ok
    # -------------------------------------------------------------------------
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            data = resp.json()
            runner.assert_true(
                resp.status_code == 200 and data.get("status") == "ok" and "timestamp" in data,
                "Health /health returns 200 ok",
                f"code={resp.status_code}, data={data}",
            )
    except Exception as exc:
        runner.assert_true(False, "Health /health returns 200 ok", str(exc))

    # -------------------------------------------------------------------------
    # 10. Health /ready returns 200 when Postgres and Redis are healthy
    # -------------------------------------------------------------------------
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/ready")
            data = resp.json()
            runner.assert_true(
                resp.status_code == 200 and data.get("ready") is True and data.get("details", {}).get("redis") == "ok",
                "Health /ready returns 200 when dependencies are healthy",
                f"code={resp.status_code}, data={data}",
            )
    except Exception as exc:
        runner.assert_true(False, "Health /ready returns 200 when dependencies are healthy", str(exc))

    # -------------------------------------------------------------------------
    # 11. Health /ready with Redis down -> 503
    # -------------------------------------------------------------------------
    try:
        transport = ASGITransport(app=app)
        orig_redis_url = settings.REDIS_URL
        # Point to unreachable port with fast timeout
        settings.REDIS_URL = "redis://127.0.0.1:63999"
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/ready")
            data = resp.json()
            runner.assert_true(
                resp.status_code == 503 and data.get("ready") is False,
                "Health /ready with Redis down returns 503",
                f"code={resp.status_code}, data={data}",
            )
        settings.REDIS_URL = orig_redis_url
    except Exception as exc:
        settings.REDIS_URL = orig_redis_url
        runner.assert_true(False, "Health /ready with Redis down returns 503", str(exc))

    # -------------------------------------------------------------------------
    # 12. Health /ready with Postgres down -> 503
    # -------------------------------------------------------------------------
    try:
        transport = ASGITransport(app=app)
        with patch("sqlalchemy.ext.asyncio.AsyncSession.execute", side_effect=OperationalError("connection lost", {}, None)):
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/ready")
                data = resp.json()
                runner.assert_true(
                    resp.status_code == 503 and data.get("ready") is False,
                    "Health /ready with Postgres down returns 503",
                    f"code={resp.status_code}, data={data}",
                )
    except Exception as exc:
        runner.assert_true(False, "Health /ready with Postgres down returns 503", str(exc))

    # -------------------------------------------------------------------------
    # 13. Worker context helper get_db_session yields valid session
    # -------------------------------------------------------------------------
    try:
        ctx: dict = {}
        await base_startup(ctx)
        async with get_db_session(ctx) as session:
            runner.assert_true(
                session is not None and hasattr(session, "execute"),
                "Worker context helper get_db_session yields valid session",
            )
    except Exception as exc:
        runner.assert_true(False, "Worker context helper get_db_session yields valid session", str(exc))

    # -------------------------------------------------------------------------
    # 14. Worker graceful shutdown: lifecycle hooks execute cleanly
    # -------------------------------------------------------------------------
    try:
        ctx = {}
        await base_startup(ctx)
        # Verify logger is attached and startup succeeded
        has_logger = "logger" in ctx
        # Run shutdown hook cleanly
        await base_shutdown(ctx)
        runner.assert_true(
            has_logger,
            "Worker graceful shutdown lifecycle hooks execute cleanly",
        )
    except Exception as exc:
        runner.assert_true(False, "Worker graceful shutdown lifecycle hooks execute cleanly", str(exc))

    # -------------------------------------------------------------------------
    # 15. Docker compose validation: docker-compose config exits 0
    # -------------------------------------------------------------------------
    try:
        compose_file = ROOT / "docker-compose.yml"
        if not compose_file.exists():
            compose_file = ROOT.parent / "docker-compose.yml"

        docker_bin = shutil.which("docker-compose") or shutil.which("docker")
        if docker_bin and compose_file.exists():
            cmd = ["docker-compose", "-f", str(compose_file), "config"]
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
            runner.assert_true(
                proc.returncode == 0,
                "Docker compose validation: docker-compose config exits 0",
                f"returncode={proc.returncode}, stderr={proc.stderr}",
            )
        else:
            runner.skip("Docker compose validation", "docker-compose or config file not found")
    except Exception as exc:
        runner.assert_true(False, "Docker compose validation: docker-compose config exits 0", str(exc))

    # Cleanup open Redis connection
    if pool is not None:
        await pool.aclose()
    await close_redis_pool()


if __name__ == "__main__":
    test_runner = TestRunner()
    print("\n🔍 RUNNING RT-1 INFRASTRUCTURE TESTS\n" + "=" * 60)
    asyncio.run(run_rt_infrastructure_tests(test_runner))
    sys.exit(test_runner.report())
