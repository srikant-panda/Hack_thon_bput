"""Dead Letter Queue (DLQ) operations, manual retry, and management API routes (RT-10)."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Optional
import uuid

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, PermissionDeniedError
from app.core.security import CurrentUser, get_current_user
from app.db.admin import _get_admin_session_maker
from app.db.models import AuditLog, JobQueue, OrganizationMember, User
from app.db.session import get_db
from app.queue.client import enqueue
from app.services.job_state_service import update_job_status

logger = logging.getLogger("cyberguard.dlq")

router = APIRouter(prefix="/dlq", tags=["Dead Letter Queue"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class JobDetailResponse(BaseModel):
    id: str
    job_id: str
    job_type: str
    owner_user_id: str
    status: str
    retry_count: int
    max_retries: int
    payload: dict[str, Any]
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    next_retry_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_history: list[dict[str, Any]] = []

    model_config = {"from_attributes": True}


class DLQListResponse(BaseModel):
    jobs: list[JobDetailResponse]
    total: int
    page: int
    limit: int


class DLQStatsResponse(BaseModel):
    total_dead_letter: int
    by_job_type: dict[str, int]
    oldest_age_hours: float


class RetryJobResponse(BaseModel):
    status: str
    job_id: str
    message: str


class DeleteJobResponse(BaseModel):
    status: str
    job_id: str
    message: str


# ---------------------------------------------------------------------------
# RBAC & Authorization Dependency
# ---------------------------------------------------------------------------

async def get_dlq_user(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """Validate user permissions for DLQ operations.

    - Analyst role is strictly forbidden (HTTP 403).
    - Admins have full access across all tenant boundaries.
    """
    # 1. Direct role check on identity object
    role = getattr(user, "role", None)
    if role:
        r_lower = role.lower()
        if r_lower == "analyst":
            raise PermissionDeniedError("Analyst role is not authorized for DLQ operations")
        if r_lower in ("admin", "owner", "superadmin"):
            return user

    # 2. Database role check (e.g. if member of active org)
    user_stmt = select(User).where(User.id == user.id)
    db_user = (await db.execute(user_stmt)).scalar_one_or_none()
    if db_user and db_user.active_organization_id:
        m_stmt = select(OrganizationMember).where(
            OrganizationMember.organization_id == db_user.active_organization_id,
            OrganizationMember.user_id == user.id,
        )
        member = (await db.execute(m_stmt)).scalar_one_or_none()
        if member and member.role.lower() == "analyst":
            raise PermissionDeniedError("Analyst role is not authorized for DLQ operations")

    return user


def _build_job_response(job: JobQueue) -> JobDetailResponse:
    # Synthesize retry history records from payload / metadata if present
    retry_history = []
    if job.payload and isinstance(job.payload, dict):
        retry_history = job.payload.get("retry_history") or []
    if not retry_history and job.error:
        retry_history = [
            {
                "attempt": job.retry_count,
                "error": job.error,
                "timestamp": (job.updated_at or job.created_at).isoformat(),
            }
        ]

    return JobDetailResponse(
        id=job.id,
        job_id=job.job_id,
        job_type=job.job_type,
        owner_user_id=job.owner_user_id,
        status=job.status,
        retry_count=job.retry_count,
        max_retries=job.max_retries,
        payload=job.payload or {},
        result=job.result,
        error=job.error,
        next_retry_at=job.next_retry_at,
        created_at=job.created_at,
        updated_at=job.updated_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        retry_history=retry_history,
    )


# ---------------------------------------------------------------------------
# DLQ Routes
# ---------------------------------------------------------------------------

@router.get("/jobs", response_model=DLQListResponse)
async def list_dead_letter_jobs(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    job_type: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    owner_user_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(get_dlq_user),
) -> DLQListResponse:
    """List paginated dead-letter jobs with filtering by job_type, date range, and owner."""
    admin_maker = _get_admin_session_maker()
    async with admin_maker() as session:
        query = select(JobQueue).where(JobQueue.status == "dead_letter")

        is_admin = getattr(user, "role", "admin") == "admin"
        if not is_admin:
            # Non-admin sees only own records
            query = query.where(JobQueue.owner_user_id == user.id)
        elif owner_user_id:
            query = query.where(JobQueue.owner_user_id == owner_user_id)

        if job_type:
            query = query.where(JobQueue.job_type == job_type)
        if from_date:
            query = query.where(JobQueue.created_at >= from_date)
        if to_date:
            query = query.where(JobQueue.created_at <= to_date)

        # Count total matching
        count_stmt = select(func.count()).select_from(query.subquery())
        total = (await session.execute(count_stmt)).scalar() or 0

        # Paginated fetch
        offset = (page - 1) * limit
        paged_query = query.order_by(JobQueue.created_at.desc()).offset(offset).limit(limit)
        rows = (await session.execute(paged_query)).scalars().all()

        job_responses = [_build_job_response(j) for j in rows]
        return DLQListResponse(jobs=job_responses, total=total, page=page, limit=limit)


@router.get("/stats", response_model=DLQStatsResponse)
async def get_dlq_stats(
    user: CurrentUser = Depends(get_dlq_user),
) -> DLQStatsResponse:
    """Return aggregated metrics for dead-letter jobs including count, type breakdown, and age."""
    admin_maker = _get_admin_session_maker()
    async with admin_maker() as session:
        query = select(JobQueue).where(JobQueue.status == "dead_letter")
        if getattr(user, "role", "admin") != "admin":
            query = query.where(JobQueue.owner_user_id == user.id)

        rows = (await session.execute(query)).scalars().all()

        total = len(rows)
        by_job_type: dict[str, int] = {
            "gmail_sync": 0,
            "email_fetch": 0,
            "email_analysis": 0,
        }

        oldest_dt: Optional[datetime] = None
        for j in rows:
            by_job_type[j.job_type] = by_job_type.get(j.job_type, 0) + 1
            if oldest_dt is None or j.created_at < oldest_dt:
                oldest_dt = j.created_at

        oldest_age_hours = 0.0
        if oldest_dt is not None:
            now = datetime.now(timezone.utc)
            # Ensure timezone awareness for subtraction
            if oldest_dt.tzinfo is None:
                oldest_dt = oldest_dt.replace(tzinfo=timezone.utc)
            age_s = (now - oldest_dt).total_seconds()
            oldest_age_hours = max(0.0, round(age_s / 3600.0, 2))

        return DLQStatsResponse(
            total_dead_letter=total,
            by_job_type=by_job_type,
            oldest_age_hours=oldest_age_hours,
        )


@router.get("/jobs/{job_id}", response_model=JobDetailResponse)
async def get_dead_letter_job(
    job_id: str,
    user: CurrentUser = Depends(get_dlq_user),
) -> JobDetailResponse:
    """Retrieve full job detail including payload, failure reason, and execution history."""
    admin_maker = _get_admin_session_maker()
    async with admin_maker() as session:
        query = select(JobQueue).where(JobQueue.job_id == job_id)
        if getattr(user, "role", "admin") != "admin":
            query = query.where(JobQueue.owner_user_id == user.id)

        job = (await session.execute(query)).scalar_one_or_none()
        if job is None:
            raise NotFoundError("Dead letter job", job_id)

        return _build_job_response(job)


@router.post("/jobs/{job_id}/retry", response_model=RetryJobResponse)
async def retry_dead_letter_job(
    job_id: str,
    user: CurrentUser = Depends(get_dlq_user),
) -> RetryJobResponse:
    """Reset job state to 'queued', re-enqueue to worker queue, and record audit log."""
    if getattr(user, "role", "admin") != "admin":
        raise PermissionDeniedError("Admin privileges required to retry dead letter jobs")
    admin_maker = _get_admin_session_maker()
    async with admin_maker() as session:
        query = select(JobQueue).where(JobQueue.job_id == job_id)
        job = (await session.execute(query)).scalar_one_or_none()
        if job is None:
            raise NotFoundError("Dead letter job", job_id)

        # 1. Update job status to 'queued', reset retry_count to 0
        now = datetime.now(timezone.utc)
        job.status = "queued"
        job.retry_count = 0
        job.error = None
        job.next_retry_at = None
        job.updated_at = now

        # 2. Record manual retry audit log row
        audit = AuditLog(
            id=str(uuid.uuid4()),
            user_id=user.id,
            user_name=user.username or user.full_name or "Admin",
            actor_type="user",
            action="manual_dlq_retry",
            resource=f"job:{job.job_id}",
            details="manual retry by admin",
            owner_user_id=job.owner_user_id,
            created_at=now,
        )
        session.add(audit)
        await session.commit()
        await session.refresh(job)

    # 3. Re-enqueue to Redis/Arq
    try:
        await enqueue(job.job_type, kwargs=job.payload, job_id=job.job_id)
    except Exception as exc:
        logger.warning("Could not re-enqueue job %s to Redis: %s", job_id, exc)

    logger.info("Admin %s manually retried dead letter job %s (type=%s)", user.id, job_id, job.job_type)
    return RetryJobResponse(
        status="queued",
        job_id=job.job_id,
        message="Job reset to queued and re-enqueued to worker pool",
    )


@router.delete("/jobs/{job_id}", response_model=DeleteJobResponse)
async def delete_dead_letter_job(
    job_id: str,
    user: CurrentUser = Depends(get_dlq_user),
) -> DeleteJobResponse:
    """Soft-delete a dead-letter job (status='deleted') to preserve audit trail."""
    if getattr(user, "role", "admin") != "admin":
        raise PermissionDeniedError("Admin privileges required to delete dead letter jobs")
    admin_maker = _get_admin_session_maker()
    async with admin_maker() as session:
        query = select(JobQueue).where(JobQueue.job_id == job_id)
        job = (await session.execute(query)).scalar_one_or_none()
        if job is None:
            raise NotFoundError("Dead letter job", job_id)

        now = datetime.now(timezone.utc)
        job.status = "deleted"
        job.updated_at = now

        # Record deletion in audit log
        audit = AuditLog(
            id=str(uuid.uuid4()),
            user_id=user.id,
            user_name=user.username or user.full_name or "Admin",
            actor_type="user",
            action="manual_dlq_delete",
            resource=f"job:{job.job_id}",
            details="Job soft-deleted from DLQ",
            owner_user_id=job.owner_user_id,
            created_at=now,
        )
        session.add(audit)
        await session.commit()

    logger.info("Admin %s soft-deleted dead letter job %s", user.id, job_id)
    return DeleteJobResponse(
        status="deleted",
        job_id=job_id,
        message="Job marked as deleted",
    )
