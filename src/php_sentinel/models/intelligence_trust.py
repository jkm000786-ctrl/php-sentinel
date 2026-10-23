from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import (
    BaseModel,
    Field,
    model_validator,
)


class IntelligenceTrustState(str, Enum):
    BUNDLED_TRUSTED = "bundled_trusted"
    TRUSTED = "trusted"
    UNSIGNED = "unsigned"
    UNKNOWN_SIGNER = "unknown_signer"
    INVALID_SIGNATURE = "invalid_signature"
    DIGEST_MISMATCH = "digest_mismatch"
    METADATA_MISMATCH = "metadata_mismatch"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"


class IntelligenceManifest(BaseModel):
    manifest_version: int = Field(
        default=2,
        ge=1,
    )
    policy_id: str = Field(
        min_length=1,
    )
    schema_version: int = Field(
        ge=1,
    )
    policy_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    # Phase 15 lifecycle metadata.
    generation: int | None = Field(
        default=None,
        ge=1,
    )
    issued_at: datetime
    expires_at: datetime | None = None

    signer_id: str = Field(
        min_length=1,
    )
    algorithm: Literal["ed25519"] = "ed25519"
    signature_b64: str = Field(
        min_length=1,
    )

    @model_validator(mode="after")
    def validate_lifecycle(
        self,
    ) -> IntelligenceManifest:
        if self.issued_at.tzinfo is None:
            raise ValueError("Manifest issued_at must include timezone information.")

        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("Manifest expires_at must include timezone information.")

        if self.manifest_version >= 2:
            if self.generation is None:
                raise ValueError("Manifest v2 requires generation.")

            if self.expires_at is None:
                raise ValueError("Manifest v2 requires expires_at.")

        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("Manifest expires_at must be later than issued_at.")

        return self


class TrustedSigner(BaseModel):
    signer_id: str = Field(
        min_length=1,
    )
    algorithm: Literal["ed25519"] = "ed25519"
    public_key_b64: str = Field(
        min_length=1,
    )
    enabled: bool = True


class TrustStore(BaseModel):
    store_version: int = Field(
        default=1,
        ge=1,
    )
    signers: list[TrustedSigner] = Field(
        default_factory=list,
    )

    @model_validator(mode="after")
    def validate_unique_signers(
        self,
    ) -> TrustStore:
        ids = [signer.signer_id for signer in self.signers]

        if len(ids) != len(set(ids)):
            raise ValueError("Trusted signer IDs must be unique.")

        return self


class IntelligenceTrustDecision(BaseModel):
    state: IntelligenceTrustState
    trusted: bool
    policy_id: str
    policy_sha256: str
    signer_id: str | None = None
    algorithm: str | None = None
    rationale: list[str] = Field(
        default_factory=list,
    )
