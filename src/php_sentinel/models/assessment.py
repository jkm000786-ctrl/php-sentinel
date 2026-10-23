from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from .evidence import Evidence
from .fingerprint import Fingerprint


class AssessmentStatus(str, Enum):
    NOT_PHP = "not_php"
    PATCHED_UPSTREAM = "patched_upstream"
    NEEDS_VENDOR_EVIDENCE = "needs_vendor_evidence"
    INCONCLUSIVE = "inconclusive"


class Assessment(BaseModel):
    target: str
    php_detected: bool = False
    php_version: str | None = None
    php_confidence: float = 0.0
    server: str | None = None
    x_powered_by: str | None = None
    fingerprint: Fingerprint = Field(default_factory=Fingerprint)
    exposure_priority: str = "unknown"
    status: AssessmentStatus = AssessmentStatus.INCONCLUSIVE
    applicable_cves: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
