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
    username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, unique=True, index=True)
    account_type: Mapped[str] = mapped_column(String(16), default="user")  # 'user' | 'organization' (frozen)
    # Notification address (Phase 7) — strictly separate from any connected
    # mailbox; system notifications NEVER go to connected mailboxes.
    notification_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
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
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
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
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
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
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
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
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
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
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
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
    # user | system | scheduler — distinguishes automated vs user-initiated.
    actor_type: Mapped[str] = mapped_column(String(16), default="user")
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="audit_logs")


class EnforcementPolicy(Base):
    __tablename__ = "enforcement_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    # Nullable: personal-workspace policies carry organization_id = NULL and are
    # owner-scoped via owner_user_id instead.
    organization_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
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


class EmailConnectorAccount(Base):
    __tablename__ = "email_connector_accounts"
    __table_args__ = (
        UniqueConstraint("owner_user_id", "provider", "provider_email", name="uq_connector_owner_provider_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # gmail | outlook | yahoo | icloud
    provider_email: Mapped[str] = mapped_column(String(255), nullable=False)
    # connected | reauth_required | revoked | error
    status: Mapped[str] = mapped_column(String(32), default="connected", index=True)
    scopes: Mapped[list[Any]] = mapped_column(PortableJSON, default=list)
    capabilities: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)

    # Encrypted at rest (app.core.crypto); never returned by any API.
    access_token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    refresh_token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    access_token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)


class ConnectorOAuthState(Base):
    __tablename__ = "connector_oauth_states"

    state: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    redirect_after: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class ConnectorOperationLog(Base):
    __tablename__ = "connector_operation_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    connector_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    # authorize | callback | token_refresh | test_connection | disconnect
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    # success | failed | unsupported | insufficient_scope | reauth_required
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    provider_error_code: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    provider_error_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)


class ConnectorSettings(Base):
    __tablename__ = "connector_settings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    connector_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    # Hours until a quarantined message auto-releases; NULL = manual (never expire).
    quarantine_expiry_hours: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    permanent_delete_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_quarantine_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)


class QuarantinedItem(Base):
    __tablename__ = "quarantined_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    connector_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    provider_message_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    # Full Phase 3 ScanResult, stored for the review view.
    scan_result_json: Mapped[dict[str, Any]] = mapped_column(PortableJSON, default=dict)
    quarantined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # quarantined | released | deleted | expired
    status: Mapped[str] = mapped_column(String(32), default="quarantined", index=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class BlockedSender(Base):
    __tablename__ = "blocked_senders"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    connector_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False)
    # Gmail filter id; NULL when rule creation failed or is not applicable.
    provider_rule_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # blocked | released | expired
    status: Mapped[str] = mapped_column(String(32), default="blocked", index=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class SecurityEvent(Base):
    """Permanent security history: one row per real security event / provider
    operation (Phase 5). AI chat content is NEVER written here."""

    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    # scan_verdict | quarantine | release | keep | delete | sender_block |
    # sender_release | sender_expiry | connector_connect |
    # connector_disconnect | connector_test | enforcement_decision |
    # sender_trust | sender_untrust
    event_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    connector_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("email_connector_accounts.id", ondelete="SET NULL"), nullable=True,
    )
    provider: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    provider_message_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    sender_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    indicators: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(PortableJSON, nullable=True)
    action_requested: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    action_performed: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # user | system | scheduler
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="user", index=True)
    # success | failed | unsupported | insufficient_scope | reauth_required
    operation_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    operation_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    quarantined_item_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("quarantined_items.id", ondelete="SET NULL"), nullable=True,
    )
    blocked_sender_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("blocked_senders.id", ondelete="SET NULL"), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)


class NotificationLog(Base):
    """Delivery log for event email notifications (Phase 7).

    Recipient is ALWAYS the user's notification_email — never a connected
    mailbox. The default backend is DB-logged delivery (hackathon-demo safe);
    optional SMTP is best-effort with fallback to DB logging.
    """

    __tablename__ = "notification_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # sent | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    error_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # db_log | smtp — how the message was actually delivered
    backend: Mapped[str] = mapped_column(String(16), default="db_log")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)


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
    owner_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

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


class TrustedSender(Base):
    """Sender trust list (FP-hardening, Deliverable 1).

    Populated explicitly by the user via "Release & trust sender" on a
    quarantined message (or from the Blocked Senders page). Trusted senders
    never auto-enforce: scans still run and verdicts are still shown, but the
    action engine becomes recommend-only for their messages with an explicit
    "sender is in your trust list" annotation.
    """

    __tablename__ = "trusted_senders"
    __table_args__ = (
        UniqueConstraint("owner_user_id", "sender_email", name="uq_trusted_sender_owner_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    sender_email: Mapped[str] = mapped_column(String(255), nullable=False)
    sender_domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Why the trust entry exists, e.g. "released: <subject>" — shown in the UI.
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)
