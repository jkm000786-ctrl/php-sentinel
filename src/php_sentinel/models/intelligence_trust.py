from __future__ import annotations

import base64
from datetime import datetime
from enum import Enum

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
)

SUPPORTED_TRUST_STORE_VERSIONS = frozenset({1})

ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64


class IntelligenceTrustState(str, Enum):
    BUNDLED_TRUSTED = "bundled_trusted"
    TRUSTED = "trusted"
    UNSIGNED = "unsigned"
    UNKNOWN_SIGNER = "unknown_signer"
    INVALID_SIGNATURE = "invalid_signature"
    DIGEST_MISMATCH = "digest_mismatch"
    METADATA_MISMATCH = "metadata_mismatch"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"


def _validate_strict_base64_length(
    value: str,
    *,
    expected_length: int,
    field_name: str,
) -> str:
    try:
        raw = base64.b64decode(
            value,
            validate=True,
        )
    except ValueError as exc:
        raise ValueError(f"{field_name} must use strict base64.") from exc

    if len(raw) != expected_length:
        raise ValueError(f"{field_name} must decode to exactly {expected_length} bytes.")

    return value


class SignerDelegation(BaseModel):
    delegation_version: int = Field(
        default=1,
        ge=1,
    )

    context: str = Field(
        pattern=r"^(intelligence|registry)$",
    )

    predecessor_signer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    successor_signer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    successor_public_key_b64: str = Field(
        min_length=1,
    )

    sequence: int = Field(
        ge=1,
    )

    minimum_successor_generation: int = Field(
        ge=1,
    )

    issued_at: datetime
    expires_at: datetime

    algorithm: str = "ed25519"

    signature_b64: str = Field(
        min_length=1,
    )

    @field_validator("successor_public_key_b64")
    @classmethod
    def validate_successor_public_key(
        cls,
        value: str,
    ) -> str:
        return _validate_strict_base64_length(
            value,
            expected_length=(ED25519_PUBLIC_KEY_BYTES),
            field_name=("successor_public_key_b64"),
        )

    @field_validator("signature_b64")
    @classmethod
    def validate_delegation_signature(
        cls,
        value: str,
    ) -> str:
        return _validate_strict_base64_length(
            value,
            expected_length=(ED25519_SIGNATURE_BYTES),
            field_name="signature_b64",
        )

    @model_validator(mode="after")
    def validate_delegation(
        self,
    ) -> SignerDelegation:
        if self.delegation_version != 1:
            raise ValueError("Unsupported signer-delegation version.")

        if self.predecessor_signer_id == self.successor_signer_id:
            raise ValueError("A signer cannot delegate rotation to itself.")

        if self.issued_at.tzinfo is None:
            raise ValueError("Delegation issued_at requires timezone information.")

        if self.expires_at.tzinfo is None:
            raise ValueError("Delegation expires_at requires timezone information.")

        if self.expires_at <= self.issued_at:
            raise ValueError("Delegation expires_at must be later than issued_at.")

        return self


class SignerDelegationRevocation(BaseModel):
    revocation_version: int = Field(
        default=1,
        ge=1,
    )

    context: str = Field(
        pattern=r"^(intelligence|registry)$",
    )

    predecessor_signer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    successor_signer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    delegation_sequence: int = Field(
        ge=1,
    )

    delegation_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    revocation_sequence: int = Field(
        ge=1,
    )

    issued_at: datetime

    algorithm: str = "ed25519"

    signature_b64: str = Field(
        min_length=1,
    )

    @field_validator("signature_b64")
    @classmethod
    def validate_revocation_signature(
        cls,
        value: str,
    ) -> str:
        return _validate_strict_base64_length(
            value,
            expected_length=(ED25519_SIGNATURE_BYTES),
            field_name="signature_b64",
        )

    @model_validator(mode="after")
    def validate_revocation(
        self,
    ) -> SignerDelegationRevocation:
        if self.revocation_version != 1:
            raise ValueError("Unsupported signer-delegation revocation version.")

        if self.predecessor_signer_id == self.successor_signer_id:
            raise ValueError("A signer cannot revoke a self-delegation.")

        if self.issued_at.tzinfo is None:
            raise ValueError("Delegation revocation issued_at requires timezone information.")

        return self


class VerifiedSignerDelegationEvidence(BaseModel):
    predecessor_signer_id: str
    successor_signer_id: str

    sequence: int = Field(
        ge=1,
    )

    minimum_successor_generation: int = Field(
        ge=1,
    )

    delegation_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )


class IntelligenceManifest(BaseModel):
    manifest_version: int = Field(
        default=3,
        ge=1,
    )

    policy_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    schema_version: int = Field(
        ge=1,
    )

    policy_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    generation: int | None = Field(
        default=None,
        ge=1,
    )

    issued_at: datetime
    expires_at: datetime | None = None

    signer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    # String rather than Literal so unsupported algorithms can reach
    # the verifier and produce an explicit diagnostic state.
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
        return _validate_strict_base64_length(
            value,
            expected_length=(ED25519_SIGNATURE_BYTES),
            field_name="signature_b64",
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
                raise ValueError("Manifest v2+ requires generation.")

            if self.expires_at is None:
                raise ValueError("Manifest v2+ requires expires_at.")

        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("Manifest expires_at must be later than issued_at.")

        return self


class TrustedSigner(BaseModel):
    signer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    algorithm: str = "ed25519"

    public_key_b64: str = Field(
        min_length=1,
    )

    enabled: bool = True

    # Explicit successor relationship for controlled key rotation.
    authorized_predecessors: list[str] = Field(
        default_factory=list,
    )

    @field_validator("public_key_b64")
    @classmethod
    def validate_public_key(
        cls,
        value: str,
    ) -> str:
        return _validate_strict_base64_length(
            value,
            expected_length=(ED25519_PUBLIC_KEY_BYTES),
            field_name="public_key_b64",
        )


class TrustStore(BaseModel):
    store_version: int = 1

    signers: list[TrustedSigner] = Field(
        default_factory=list,
    )

    delegations: list[SignerDelegation] = Field(
        default_factory=list,
    )

    delegation_revocations: list[SignerDelegationRevocation] = Field(
        default_factory=list,
    )

    @model_validator(mode="after")
    def validate_store(
        self,
    ) -> TrustStore:
        if self.store_version not in SUPPORTED_TRUST_STORE_VERSIONS:
            raise ValueError(
                "Unsupported trust-store version "
                f"{self.store_version}. Supported: "
                f"{sorted(SUPPORTED_TRUST_STORE_VERSIONS)}."
            )

        ids = [signer.signer_id for signer in self.signers]

        if len(ids) != len(set(ids)):
            raise ValueError("Trusted signer IDs must be unique.")

        for signer in self.signers:
            if signer.signer_id in signer.authorized_predecessors:
                raise ValueError("A signer cannot authorize itself as a predecessor.")

        delegation_ids = [
            (
                item.context,
                item.predecessor_signer_id,
                item.successor_signer_id,
                item.sequence,
            )
            for item in self.delegations
        ]

        if len(delegation_ids) != len(set(delegation_ids)):
            raise ValueError("Signer delegation identity tuples must be unique.")

        revocation_ids = [
            (
                item.context,
                item.predecessor_signer_id,
                item.successor_signer_id,
                item.delegation_sequence,
                item.revocation_sequence,
            )
            for item in self.delegation_revocations
        ]

        if len(revocation_ids) != len(set(revocation_ids)):
            raise ValueError("Signer delegation revocation identity tuples must be unique.")

        return self


class IntelligenceTrustDecision(BaseModel):
    state: IntelligenceTrustState
    trusted: bool

    policy_id: str
    policy_sha256: str

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

    authorized_predecessor_delegations: dict[
        str,
        VerifiedSignerDelegationEvidence,
    ] = Field(
        default_factory=dict,
    )

    rationale: list[str] = Field(
        default_factory=list,
    )
