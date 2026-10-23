from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class CVEDecisionStatus(str, Enum):
    PATCHED_UPSTREAM = "patched_upstream"
    PATCHED_VENDOR = "patched_vendor"
    POTENTIALLY_AFFECTED = "potentially_affected"
    NEEDS_VENDOR_EVIDENCE = "needs_vendor_evidence"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"


class DecisionConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ExposurePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    ELEVATED = "elevated"
    NONE = "none"
    UNKNOWN = "unknown"


class CVEDecision(BaseModel):
    cve_id: str
    title: str
    status: CVEDecisionStatus
    confidence: DecisionConfidence
    exposure_priority: ExposurePriority
    detected_version: str | None = None
    fixed_version: str | None = None
    rationale: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class CVEDecisionReport(BaseModel):
    php_detected: bool
    php_version: str | None = None
    vendor_family: str | None = None
    backport_status: str | None = None
    sapi_hypothesis: str | None = None
    decisions: list[CVEDecision] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
