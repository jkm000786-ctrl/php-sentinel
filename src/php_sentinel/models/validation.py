from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class ValidationKind(str, Enum):
    BASELINE_GET = "baseline_get"
    HEAD_CHECK = "head_check"


class ValidationObservation(BaseModel):
    kind: ValidationKind
    method: str
    url: str
    status_code: int
    server: str | None = None
    x_powered_by: str | None = None
    content_type: str | None = None
    body_sha256: str | None = None
    body_length: int | None = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ValidationReport(BaseModel):
    target: str
    authorized: bool
    lab_only: bool = True
    observations: list[ValidationObservation] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
