from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class FindingState(str, Enum):
    PATCHED = "patched"
    POTENTIAL_EXPOSURE = "potential_exposure"
    NEEDS_EVIDENCE = "needs_evidence"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Finding(BaseModel):
    finding_id: str
    cve_id: str
    title: str
    state: FindingState
    severity: FindingSeverity
    confidence: str
    target: str
    detected_version: str | None = None
    fixed_version: str | None = None
    sapi_hypothesis: str | None = None
    evidence: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
