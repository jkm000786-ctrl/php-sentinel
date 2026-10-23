from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class IntelligenceLifecycleState(
    str,
    Enum,
):
    CURRENT = "current"
    STALE = "stale"
    EXPIRED = "expired"
    ROLLBACK_DETECTED = "rollback_detected"
    REPLAY_DETECTED = "replay_detected"
    BELOW_MINIMUM_GENERATION = "below_minimum_generation"
    FUTURE_ISSUED = "future_issued"
    LEGACY_NO_LIFECYCLE = "legacy_no_lifecycle"
    SIGNER_CHANGED = "signer_changed"


class IntelligenceLifecyclePolicy(BaseModel):
    minimum_generation: int = Field(
        default=1,
        ge=1,
    )
    maximum_age_days: int = Field(
        default=30,
        ge=1,
    )
    maximum_future_skew_seconds: int = Field(
        default=300,
        ge=0,
    )


class IntelligenceLifecycleDecision(BaseModel):
    state: IntelligenceLifecycleState
    activatable: bool

    policy_id: str
    policy_sha256: str

    generation: int | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    signer_id: str | None = None

    minimum_generation: int | None = None
    maximum_age_days: int | None = None

    rationale: list[str] = Field(
        default_factory=list,
    )


class LifecycleStateRecord(BaseModel):
    generation: int = Field(
        ge=1,
    )
    policy_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )
    signer_id: str
    accepted_at: datetime


class LifecycleStateStore(BaseModel):
    store_version: int = Field(
        default=1,
        ge=1,
    )
    records: dict[
        str,
        LifecycleStateRecord,
    ] = Field(
        default_factory=dict,
    )
