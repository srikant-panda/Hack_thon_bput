"""Verbose scan result schemas for mailbox analysis (Phase 3).

Analysis-only phase: any enforcement action is reported honestly as
``provider_operation_status = "deferred_to_phase_4"`` — the system recommends
quarantine but never pretends it happened.
"""

from typing import Optional

from pydantic import BaseModel, Field

# Honest provider-operation status values.
OPERATION_DEFERRED = "deferred_to_phase_4"
OPERATION_NONE_REQUIRED = "no_action_required"


class Indicator(BaseModel):
    name: str
    value: str
    weight: float


class FeatureAnalysis(BaseModel):
    engine: str          # e.g. "phishing_detector", "url_detector"
    severity: str        # safe | low | medium | high | critical
    score: float         # 0.0 - 1.0
    explanation: str     # verbose human-readable explanation
    indicators: list[Indicator] = Field(default_factory=list)


class ScanResult(BaseModel):
    message_id: str
    provider: str = "gmail"
    sender: str = ""
    subject: str = ""
    received_at: Optional[str] = None
    overall_severity: str
    overall_score: float          # 0.0 - 1.0
    overall_explanation: str
    feature_analyses: list[FeatureAnalysis] = Field(default_factory=list)
    recommended_action: str       # e.g. "quarantine", "flag_for_review", "none"
    provider_operation_status: str
    provider_operation_detail: Optional[str] = None
