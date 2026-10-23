from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ComparisonState(str, Enum):
    REMEDIATED = "remediated"
    REGRESSED = "regressed"
    UNCHANGED = "unchanged"
    EVIDENCE_CHANGED = "evidence_changed"
    POLICY_CHANGED = "policy_changed"
    TRUST_CHANGED = "trust_changed"
    INCOMPARABLE = "incomparable"


class CVEChange(BaseModel):
    cve_id: str
    before_state: str | None = None
    after_state: str | None = None
    before_severity: str | None = None
    after_severity: str | None = None
    transition: ComparisonState


class ComparisonReport(BaseModel):
    before_report_id: str
    after_report_id: str
    before_target: str
    after_target: str
    overall_state: ComparisonState

    same_requested_target: bool
    same_target_identity: bool
    same_policy_version: bool
    same_canonical_evidence: bool

    same_intelligence_policy: bool | None = None
    same_intelligence_trust: bool | None = None

    intelligence_policy_before: str | None = None
    intelligence_policy_after: str | None = None
    intelligence_sha256_before: str | None = None
    intelligence_sha256_after: str | None = None

    intelligence_trust_before: str | None = None
    intelligence_trust_after: str | None = None
    intelligence_signer_before: str | None = None
    intelligence_signer_after: str | None = None

    php_version_before: str | None = None
    php_version_after: str | None = None

    assessment_before: str
    assessment_after: str

    changes: list[str] = Field(default_factory=list)
    cve_changes: list[CVEChange] = Field(default_factory=list)
