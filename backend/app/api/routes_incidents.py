"""Incident management endpoints using Async SQLAlchemy."""

from typing import Any, Optional

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TenantContext, require_role
from app.db.session import get_db
from app.schemas.incidents import (
    IncidentAssign,
    IncidentCreate,
    IncidentEscalate,
    IncidentResponse,
    IncidentStatusUpdate,
)
from app.services import incident_service

router = APIRouter(prefix="/incidents", tags=["Incidents"])


def _format_incident(incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "assigned_to": incident.assigned_to,
        "linked_alert_ids": [link.alert_id for link in incident.alert_links],
        "timeline": [
            {
                "id": ev.id,
                "action": ev.action,
                "actor": ev.actor,
                "details": ev.details,
                "created_at": ev.created_at,
            }
            for ev in incident.timeline
        ],
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
    }


@router.get("", response_model=list[IncidentResponse])
async def list_incidents(
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> list[dict[str, Any]]:
    """List incidents scoped to the active organization, optionally filtered by status."""
    incidents = await incident_service.list_incidents(
        db, tenant=tenant, status_filter=status_filter
    )
    return [_format_incident(inc) for inc in incidents]


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst", "viewer"])),
) -> dict[str, Any]:
    """Fetch a single incident with its timeline and linked alerts."""
    incident = await incident_service.get_incident(
        db, incident_id=incident_id, tenant=tenant
    )
    return _format_incident(incident)


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict[str, Any]:
    """Create an incident, optionally linking existing alerts (analysts and admins)."""
    incident = await incident_service.create_incident(
        db,
        tenant=tenant,
        title=payload.title,
        severity=payload.severity,
        linked_alert_ids=payload.linked_alert_ids,
        created_by=tenant.user_email or tenant.user_id,
    )
    return _format_incident(incident)


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict[str, Any]:
    """Change an incident's status."""
    incident = await incident_service.update_incident_status(
        db,
        incident_id=incident_id,
        tenant=tenant,
        new_status=payload.status,
        actor=tenant.user_email or tenant.user_id,
    )
    return _format_incident(incident)


@router.patch("/{incident_id}/assign", response_model=IncidentResponse)
async def assign_incident(
    incident_id: str,
    payload: IncidentAssign,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict[str, Any]:
    """Assign an incident to an analyst."""
    incident = await incident_service.assign_incident(
        db,
        incident_id=incident_id,
        tenant=tenant,
        assigned_to=payload.assigned_to,
        actor=tenant.user_email or tenant.user_id,
    )
    return _format_incident(incident)


@router.post("/{incident_id}/escalate", response_model=IncidentResponse)
async def escalate_incident(
    incident_id: str,
    payload: IncidentEscalate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict[str, Any]:
    """Escalate an incident to critical severity with a stated reason."""
    incident = await incident_service.escalate_incident(
        db,
        incident_id=incident_id,
        tenant=tenant,
        reason=payload.reason,
        actor=tenant.user_email or tenant.user_id,
    )
    return _format_incident(incident)
