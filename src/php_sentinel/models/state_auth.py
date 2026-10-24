from __future__ import annotations

import base64

from pydantic import BaseModel, Field, field_validator, model_validator

SUPPORTED_AUTHORITY_STATE_AUTH_VERSIONS = frozenset({1})
AUTHORITY_STATE_HMAC_BYTES = 32


class AuthorityStateEnvelope(BaseModel):
    auth_version: int = Field(default=1, ge=1)

    context: str = Field(
        pattern=r"^(lifecycle|registry)$",
    )

    algorithm: str = "hmac-sha256"

    key_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    state: dict

    mac_b64: str = Field(min_length=1)

    @field_validator("mac_b64")
    @classmethod
    def validate_mac(
        cls,
        value: str,
    ) -> str:
        try:
            raw = base64.b64decode(
                value,
                validate=True,
            )
        except ValueError as exc:
            raise ValueError("Authority-state MAC must use strict base64.") from exc

        if len(raw) != AUTHORITY_STATE_HMAC_BYTES:
            raise ValueError("Authority-state MAC must decode to exactly 32 bytes.")

        return value

    @model_validator(mode="after")
    def validate_envelope(
        self,
    ) -> AuthorityStateEnvelope:
        if self.auth_version not in SUPPORTED_AUTHORITY_STATE_AUTH_VERSIONS:
            raise ValueError(
                "Unsupported authority-state authentication version "
                f"{self.auth_version}. Supported: "
                f"{sorted(SUPPORTED_AUTHORITY_STATE_AUTH_VERSIONS)}."
            )

        if self.algorithm != "hmac-sha256":
            raise ValueError("Authority-state authentication algorithm must be hmac-sha256.")

        return self
