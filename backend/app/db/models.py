"""SQLAlchemy ORM models for CYBERGUARD."""

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid_str() -> str:
    return str(uuid.uuid4())


# Portable JSON type: uses JSONB on PostgreSQL, standard JSON on SQLite
PortableJSON = JSON().with_variant(JSONB(), "postgresql")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # Supabase Auth UUID
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_single_user: Mapped[bool] = mapped_column(Boolean, default=True)
    active_organization_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    # Relationships
    memberships: Mapped[list["OrganizationMember"]] = relationship(
        "OrganizationMember", back_populates="user", cascade="all, delete-orphan"
    )
    owned_organizations: Mapped[list["Organization"]] = relationship(
        "Organization", back_populates="owner", foreign_keys="Organization.owner_id"
    )


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    is_personal: Mapped[bool] = mapped_column(Boolean, default=False)  # True for single-user workspaces
    owner_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="owned_organizations", foreign_keys=[owner_id])
    members: Mapped[list["OrganizationMember"]] = relationship(
        "OrganizationMember", back_populates="organization", cascade="all, delete-orphan"
    )
    events: Mapped[list["Event"]] = relationship("Event", back_populates="organization", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="organization", cascade="all, delete-orphan")
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident", back_populates="organization", cascade="all, delete-orphan"
    )
    executions: Mapped[list["ResponseExecution"]] = relationship(
        "ResponseExecution", back_populates="organization", cascade="all, delete-orphan"
    )
    enforcement_policies: Mapped[list["EnforcementPolicy"]] = relationship(
        "EnforcementPolicy", back_populates="organization", cascade="all, delete-orphan"
    )
    action_executions: Mapped[list["ActionExecution"]] = relationship(
        "ActionExecution", back_populates="organization", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="organization", cascade="all, delete-orphan"
    )


class OrganizationMember(Base):
    __tablename__ = "organization_members"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_org_user"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(32), default="analyst")  # 'admin', 'analyst', 'viewer'
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="members")
    user: Mapped["User"] = relationship("User", back_populates="memberships")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_data: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="received", index=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="events")
    media_files: Mapped[list["MediaFile"]] = relationship(
        "MediaFile", back_populates="event", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="event")


class MediaFile(Base):
    __tablename__ = "media_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    file_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    # Relationships
    event: Mapped["Event"] = relationship("Event", back_populates="media_files")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    event_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    module: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    threat_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    indicators: Mapped[list[dict[str, Any]]] = mapped_column(PortableJSON, default=list)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre: Mapped[list[dict[str, Any]]] = mapped_column(PortableJSON, default=list)
    target_user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    target_service: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="alerts")
    event: Mapped[Optional["Event"]] = relationship("Event", back_populates="alerts")
    recommended_actions: Mapped[list["RecommendedAction"]] = relationship(
        "RecommendedAction", back_populates="alert", cascade="all, delete-orphan", lazy="selectin"
    )
    action_executions: Mapped[list["ActionExecution"]] = relationship(
        "ActionExecution", back_populates="alert", cascade="all, delete-orphan"
    )
    incident_links: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="alert", cascade="all, delete-orphan"
    )


class RecommendedAction(Base):
    __tablename__ = "recommended_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    automation_level: Mapped[str] = mapped_column(String(32), default="manual")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    priority: Mapped[str] = mapped_column(String(32), default="low")
    executed: Mapped[bool] = mapped_column(Boolean, default=False)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    # Relationships
    alert: Mapped["Alert"] = relationship("Alert", back_populates="recommended_actions")


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="incidents")
    alert_links: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    timeline: Mapped[list["IncidentEvent"]] = relationship(
        "IncidentEvent", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True, index=True
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="alert_links")
    alert: Mapped["Alert"] = relationship("Alert", back_populates="incident_links")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline")


class ResponseCatalog(Base):
    __tablename__ = "response_catalog"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    action: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    target_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    automation_level: Mapped[str] = mapped_column(String(32), default="manual")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ResponseExecution(Base):
    __tablename__ = "response_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    catalog_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("response_catalog.id", ondelete="SET NULL"), nullable=True
    )
    action_name: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    executed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="executions")
    catalog_entry: Mapped[Optional["ResponseCatalog"]] = relationship("ResponseCatalog")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    user_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="audit_logs")


class EnforcementPolicy(Base):
    __tablename__ = "enforcement_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)  # e.g. "Strict", "Balanced", "Permissive"
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    # --- Per-threat-type risk thresholds (0-100), independent of display severity ---
    # phishing (also reused for URLs)
    phishing_high_threshold: Mapped[int] = mapped_column(Integer, default=75)
    phishing_medium_threshold: Mapped[int] = mapped_column(Integer, default=40)
    # deepfake / media
    deepfake_high_threshold: Mapped[int] = mapped_column(Integer, default=70)
    deepfake_medium_threshold: Mapped[int] = mapped_column(Integer, default=50)
    # account takeover
    ato_high_threshold: Mapped[int] = mapped_column(Integer, default=60)
    ato_medium_threshold: Mapped[int] = mapped_column(Integer, default=40)
    # network / api abuse
    network_high_threshold: Mapped[int] = mapped_column(Integer, default=70)
    network_medium_threshold: Mapped[int] = mapped_column(Integer, default=50)
    # impersonation / BEC
    impersonation_high_threshold: Mapped[int] = mapped_column(Integer, default=70)
    impersonation_medium_threshold: Mapped[int] = mapped_column(Integer, default=40)

    # --- Action per enforcement severity band ---
    action_on_critical: Mapped[str] = mapped_column(String(64), default="block_and_quarantine")
    action_on_high: Mapped[str] = mapped_column(String(64), default="block")
    action_on_medium: Mapped[str] = mapped_column(String(64), default="warn_and_log")
    action_on_low: Mapped[str] = mapped_column(String(64), default="allow")

    # --- Auto-execute toggles ---
    auto_execute_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_execute_high: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_execute_medium: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_execute_low: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- Notifications ---
    notify_soc_on_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_soc_on_high: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_user_on_medium: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="enforcement_policies", foreign_keys=[organization_id]
    )


class ActionExecution(Base):
    __tablename__ = "action_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True,
    )
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    event_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True,
    )

    # What to do
    # values: quarantine_email | block_url | drop_packet | block_ip | revoke_session |
    #         require_mfa | rate_limit | tag_and_warn | allow | flag_for_review
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # e.g. {"email_id": "...", "recipient": "..."} or {"url": "..."} or {"ip": "..."}
    target: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)

    # Lifecycle: pending | approved | executing | success | failed | rejected | skipped | released | unblocked
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    execution_mode: Mapped[str] = mapped_column(String(16), nullable=False)  # "client" | "server"

    # Origin: user | api | automated_system | webhook
    triggered_by: Mapped[str] = mapped_column(String(64), nullable=False)
    triggered_by_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Approval workflow
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Execution result, e.g. {"quarantine_id": "q_abc", "simulated": true}
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_result: Mapped[Optional[dict[str, Any]]] = mapped_column(PortableJSON, nullable=True)

    # Risk context (denormalized for fast queries)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # critical|high|medium|low
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False)  # phishing|deepfake|ato|network|impersonation
    module: Mapped[str] = mapped_column(String(64), nullable=False)  # mirrors Alert.module

    # Policy reference
    policy_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("enforcement_policies.id", ondelete="SET NULL"), nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="action_executions")
    alert: Mapped[Optional["Alert"]] = relationship("Alert", back_populates="action_executions")
    event: Mapped[Optional["Event"]] = relationship("Event")
    policy: Mapped[Optional["EnforcementPolicy"]] = relationship("EnforcementPolicy")
