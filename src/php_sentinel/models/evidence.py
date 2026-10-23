from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EvidenceKind(str, Enum):
    HTTP_HEADER = "http_header"
    BODY_MARKER = "body_marker"
    VERSION = "version"
    POLICY = "policy"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Evidence(BaseModel):
    kind: EvidenceKind
    source: str
    value: Any
    confidence: Confidence = Confidence.MEDIUM
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
