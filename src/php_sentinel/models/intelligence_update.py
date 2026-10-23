from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class IntelligenceUpdateStageMetadata(BaseModel):
    metadata_version: int = Field(
        default=1,
        ge=1,
    )

    policy_url: str
    manifest_url: str

    source_id: str | None = None
    channel: str | None = None

    fetched_at: datetime

    policy_transport_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    manifest_transport_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    policy_bytes: int = Field(
        ge=1,
    )

    manifest_bytes: int = Field(
        ge=1,
    )


class IntelligenceUpdateVerificationMetadata(BaseModel):
    metadata_version: int = Field(
        default=1,
        ge=1,
    )

    policy_id: str

    policy_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    manifest_version: int = Field(
        ge=1,
    )

    generation: int = Field(
        ge=1,
    )

    signer_id: str

    trust_state: str
    lifecycle_state: str

    trusted: bool
    activatable: bool

    verified_at: datetime

    source_policy_url: str
    source_manifest_url: str

    source_id: str | None = None
    channel: str | None = None

    staged_policy_transport_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    staged_manifest_transport_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )


class IntelligenceVerifiedCacheEntry(BaseModel):
    """
    Descriptive inspection result for one cached intelligence bundle.

    This model is not a trust capability.
    """

    path: str

    policy_id: str

    policy_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    generation: int = Field(
        ge=1,
    )

    manifest_version: int = Field(
        ge=1,
    )

    signer_id: str

    source_id: str | None = None
    channel: str | None = None

    bundle_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    verification_metadata_present: bool
    verification_metadata_consistent: bool
