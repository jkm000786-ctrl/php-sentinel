from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from php_sentinel.models.assessment import Assessment
from php_sentinel.models.cve_decision import CVEDecisionReport
from php_sentinel.models.validation import ValidationReport


class HTTPMetadata(BaseModel):
    requested_url: str
    final_url: str
    status_code: int
    redirect_count: int = 0
    content_type: str | None = None
    server: str | None = None
    x_powered_by: str | None = None
    body_length: int
    body_sha256: str


class UnifiedAssessmentReport(BaseModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    http: HTTPMetadata
    assessment: Assessment
    cve_decisions: CVEDecisionReport
    lab_validation: ValidationReport | None = None
    notes: list[str] = Field(default_factory=list)
