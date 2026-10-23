from __future__ import annotations

import base64
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator

SUPPORTED_REGISTRY_MANIFEST_VERSIONS = frozenset({1})
SUPPORTED_REGISTRY_STATE_VERSIONS = frozenset({1})

ED25519_SIGNATURE_BYTES = 64


class SourceRegistryManifest(BaseModel):
    manifest_version: int = Field(
        default=1,
        ge=1,
    )

    registry_id: str = Field(
        default="php-sentinel-source-registry",
        min_length=1,
    )

    registry_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    generation: int = Field(
        ge=1,
    )

    issued_at: datetime
    expires_at: datetime

    signer_id: str = Field(
        min_length=1,
    )

    algorithm: str = "ed25519"

    signature_b64: str = Field(
        min_length=1,
    )

    @field_validator("signature_b64")
    @classmethod
    def validate_signature(
        cls,
        value: str,
    ) -> str:
        try:
            raw = base64.b64decode(
                value,
                validate=True,
            )
        except ValueError as exc:
            raise ValueError("Registry signature must use strict base64.") from exc

        if len(raw) != ED25519_SIGNATURE_BYTES:
            raise ValueError("Registry signature must decode to exactly 64 bytes.")

        return value

    @model_validator(mode="after")
    def validate_manifest(
        self,
    ) -> SourceRegistryManifest:
        if self.manifest_version not in SUPPORTED_REGISTRY_MANIFEST_VERSIONS:
            raise ValueError(
                "Unsupported source-registry manifest version "
                f"{self.manifest_version}. Supported: "
                f"{sorted(SUPPORTED_REGISTRY_MANIFEST_VERSIONS)}."
            )

        if self.issued_at.tzinfo is None:
            raise ValueError("Registry manifest issued_at requires timezone information.")

        if self.expires_at.tzinfo is None:
            raise ValueError("Registry manifest expires_at requires timezone information.")

        if self.expires_at <= self.issued_at:
            raise ValueError("Registry manifest expires_at must be later than issued_at.")

        return self


class SourceRegistryTrustState(str, Enum):
    TRUSTED = "trusted"
    UNKNOWN_SIGNER = "unknown_signer"
    INVALID_SIGNATURE = "invalid_signature"
    DIGEST_MISMATCH = "digest_mismatch"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"


class SourceRegistryTrustDecision(BaseModel):
    state: SourceRegistryTrustState
    trusted: bool

    registry_id: str
    registry_sha256: str

    signer_id: str | None = None
    algorithm: str | None = None

    authorized_predecessor_signer_ids: list[str] = Field(
        default_factory=list,
    )

    authorized_predecessor_minimum_generations: dict[
        str,
        int,
    ] = Field(
        default_factory=dict,
    )

    rationale: list[str] = Field(
        default_factory=list,
    )


class SourceRegistryLifecycleState(str, Enum):
    CURRENT = "current"
    STALE = "stale"
    EXPIRED = "expired"
    FUTURE_ISSUED = "future_issued"
    BELOW_MINIMUM_GENERATION = "below_minimum_generation"
    ROLLBACK_DETECTED = "rollback_detected"
    REPLAY_DETECTED = "replay_detected"
    SIGNER_CHANGED = "signer_changed"


class SourceRegistryLifecycleDecision(BaseModel):
    state: SourceRegistryLifecycleState
    activatable: bool

    registry_id: str
    registry_sha256: str

    generation: int
    issued_at: datetime
    expires_at: datetime

    signer_id: str | None = None

    minimum_generation: int
    maximum_age_days: int

    rationale: list[str] = Field(
        default_factory=list,
    )


class SourceRegistryStateRecord(BaseModel):
    generation: int = Field(
        ge=1,
    )

    registry_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    signer_id: str

    accepted_at: datetime


class SourceRegistryStateStore(BaseModel):
    store_version: int = Field(
        default=1,
        ge=1,
    )

    records: dict[
        str,
        SourceRegistryStateRecord,
    ] = Field(
        default_factory=dict,
    )

    @model_validator(mode="after")
    def validate_store(
        self,
    ) -> SourceRegistryStateStore:
        if self.store_version not in SUPPORTED_REGISTRY_STATE_VERSIONS:
            raise ValueError(
                "Unsupported source-registry state version "
                f"{self.store_version}. Supported: "
                f"{sorted(SUPPORTED_REGISTRY_STATE_VERSIONS)}."
            )

        return self
