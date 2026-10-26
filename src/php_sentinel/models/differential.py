from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from php_sentinel.models.provenance import EvidenceProvenance
from php_sentinel.models.validation import ValidationReport


class DifferentialConclusion(str, Enum):
    PRECONDITION_DIFFERENTIAL_CONFIRMED = "precondition_differential_confirmed"
    BOTH_PATCHED = "both_patched"
    CANDIDATE_NOT_ESTABLISHED = "candidate_not_established"
    UNAUTHORIZED = "unauthorized"
    INCONCLUSIVE = "inconclusive"


class RuntimeSnapshot(BaseModel):
    target: str
    php_version: str | None = None
    upstream_fixed: bool | None = None
    status_code: int | None = None
    healthy: bool | None = None
    x_powered_by: str | None = None
    server: str | None = None
    body_sha256: str | None = None
    body_length: int | None = None


class DifferentialReport(BaseModel):
    candidate: RuntimeSnapshot
    patched_reference: RuntimeSnapshot
    candidate_validation: ValidationReport
    patched_validation: ValidationReport
    authorized: bool
    conclusion: DifferentialConclusion
    provenance: EvidenceProvenance | None = None
    differences: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
