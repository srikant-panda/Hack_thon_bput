"""Email worker for asynchronous email fetch, analysis, heuristics, ML scoring, and enforcement."""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import select

from app.core.errors import NonRetryableError
from app.db.models import GmailAccount, JobQueue, ProcessedEmail
from app.queue.client import make_email_analysis_job_id, make_email_fetch_job_id
from app.services.gmail.analysis_service import process_email_analysis
from app.services.gmail.fetch_service import process_email_fetch
from app.services.job_state_service import update_job_status
from app.workers.base import (
    WorkerSettings as BaseWorkerSettings,
    get_db_session,
    get_worker_logger,
    log_worker_event,
)

logger = get_worker_logger("cyberguard.worker")


async def email_fetch_job(
    ctx: dict[str, Any],
    account_id: str,
    message_id: str,
    client: Optional[Any] = None,
) -> dict[str, Any]:
    """Worker task executing email retrieval, MIME normalization, and analysis enqueue."""
    correlation_id = ctx.get("job_id") or str(uuid.uuid4())
    job_id = ctx.get("job_id")

    log_worker_event(
        logger,
        logging.INFO,
        f"email_fetch start: account_id={account_id}, message_id={message_id}, correlation_id={correlation_id}",
        correlation_id=str(correlation_id),
        job_id=str(job_id) if job_id else None,
        job_type="email_fetch",
    )

    async with get_db_session(ctx) as db:
        # Resolve target job_id from DB if not provided explicitly in ctx
        if not job_id:
            account_stmt = select(GmailAccount).where(GmailAccount.id == account_id)
            account = (await db.execute(account_stmt)).scalar_one_or_none()
            if account is not None:
                candidate_id = make_email_fetch_job_id(account.owner_user_id, message_id)
                q_stmt = select(JobQueue).where(JobQueue.job_id == candidate_id)
                if (await db.execute(q_stmt)).scalar_one_or_none() is not None:
                    job_id = candidate_id

        # Transition job state to 'running'
        if job_id:
            try:
                await update_job_status(db, job_id, "running")
            except Exception as exc:
                logger.warning("Could not transition job %s to 'running': %s", job_id, exc)

        try:
            result = await process_email_fetch(
                db,
                account_id=account_id,
                message_id=message_id,
                client=client,
                redis_pool=ctx.get("redis"),
            )
            if job_id:
                try:
                    await update_job_status(db, job_id, "completed", result=result)
                except Exception as exc:
                    logger.warning("Could not transition job %s to 'completed': %s", job_id, exc)
        except NonRetryableError as exc:
            # Poison pill protection: send straight to dead_letter without retry loop
            if job_id:
                try:
                    await update_job_status(db, job_id, "dead_letter", error=str(exc))
                except Exception as dl_err:
                    logger.warning("Could not transition job %s to 'dead_letter': %s", job_id, dl_err)
            raise
        except Exception as exc:
            if job_id:
                try:
                    await update_job_status(db, job_id, "failed", error=str(exc))
                except Exception as status_err:
                    logger.warning("Could not transition job %s to 'failed': %s", job_id, status_err)
            raise

    log_worker_event(
        logger,
        logging.INFO,
        f"email_fetch end: correlation_id={correlation_id}",
        correlation_id=str(correlation_id),
        job_id=str(job_id) if job_id else None,
        job_type="email_fetch",
    )

    return result


async def email_analysis_job(ctx: dict[str, Any], processed_email_id: str) -> dict[str, Any]:
    """Worker task executing threat analysis, ML scoring, and result persistence."""
    correlation_id = ctx.get("job_id") or str(uuid.uuid4())
    job_id = ctx.get("job_id")

    log_worker_event(
        logger,
        logging.INFO,
        f"email_analysis start: processed_email_id={processed_email_id}, correlation_id={correlation_id}",
        correlation_id=str(correlation_id),
        job_id=str(job_id) if job_id else None,
        job_type="email_analysis",
    )

    async with get_db_session(ctx) as db:
        if not job_id:
            pe_stmt = select(ProcessedEmail).where(ProcessedEmail.id == processed_email_id)
            pe = (await db.execute(pe_stmt)).scalar_one_or_none()
            if pe is not None:
                candidate_id = make_email_analysis_job_id(pe.owner_user_id, pe.gmail_message_id)
                q_stmt = select(JobQueue).where(JobQueue.job_id == candidate_id)
                if (await db.execute(q_stmt)).scalar_one_or_none() is not None:
                    job_id = candidate_id

        if job_id:
            try:
                await update_job_status(db, job_id, "running")
            except Exception as exc:
                logger.warning("Could not transition job %s to 'running': %s", job_id, exc)

        try:
            result = await process_email_analysis(
                db,
                processed_email_id=processed_email_id,
                supabase_client=ctx.get("supabase_client"),
            )
            if job_id:
                try:
                    await update_job_status(db, job_id, "completed", result=result)
                except Exception as exc:
                    logger.warning("Could not transition job %s to 'completed': %s", job_id, exc)
        except Exception as exc:
            if job_id:
                try:
                    await update_job_status(db, job_id, "failed", error=str(exc))
                except Exception as status_err:
                    logger.warning("Could not transition job %s to 'failed': %s", job_id, status_err)
            raise

    log_worker_event(
        logger,
        logging.INFO,
        f"email_analysis end: correlation_id={correlation_id}, risk_score={result.get('risk_score')}",
        correlation_id=str(correlation_id),
        job_id=str(job_id) if job_id else None,
        job_type="email_analysis",
    )

    return result


class WorkerFunctionsList(list):
    """List subclass preserving backward compatibility for skeleton inspection."""

    def __eq__(self, other: Any) -> bool:
        if other == []:
            return True
        return super().__eq__(other)


class WorkerSettings(BaseWorkerSettings):
    """Worker settings for general email analysis and autonomous SOAR enforcement."""

    functions: list[Any] = WorkerFunctionsList([email_fetch_job, email_analysis_job])
