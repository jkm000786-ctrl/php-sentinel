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
        default=1,
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
    issued_at: datetime
    signer_id: str = Field(
        min_length=1,
    )
    algorithm: Literal["ed25519"] = "ed25519"
    signature_b64: str = Field(
        min_length=1,
    )


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
