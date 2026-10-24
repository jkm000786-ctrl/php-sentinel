from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SecurityAuditEventType(StrEnum):
    UPDATE_STAGED = "update_staged"
    UPDATE_VERIFIED = "update_verified"
    UPDATE_PROMOTED = "update_promoted"
    INTELLIGENCE_ACTIVATION_ACCEPTED = "intelligence_activation_accepted"
    INTELLIGENCE_ACTIVATION_REJECTED = "intelligence_activation_rejected"
    REGISTRY_ACTIVATION_ACCEPTED = "registry_activation_accepted"
    REGISTRY_ACTIVATION_REJECTED = "registry_activation_rejected"
    REVOCATION_OBSERVED = "revocation_observed"


class SecurityAuditOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"


class SecurityAuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_version: int = Field(default=1, ge=1, le=1)
    occurred_at: datetime
    event_type: SecurityAuditEventType
    outcome: SecurityAuditOutcome

    component: str = Field(min_length=1, max_length=64)
    operation: str = Field(min_length=1, max_length=128)

    policy_id: str | None = Field(default=None, max_length=128)
    registry_id: str | None = Field(default=None, max_length=128)
    signer_id: str | None = Field(default=None, max_length=128)
    source_id: str | None = Field(default=None, max_length=128)
    channel: str | None = Field(default=None, max_length=128)

    generation: int | None = Field(default=None, ge=1)
    trust_state: str | None = Field(default=None, max_length=128)
    lifecycle_state: str | None = Field(default=None, max_length=128)

    policy_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    manifest_sha256: str | None = Field(default=None, min_length=64, max_length=64)

    reason_code: str | None = Field(default=None, max_length=128)
