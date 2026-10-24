from __future__ import annotations

import base64

from pydantic import BaseModel, Field, field_validator, model_validator

SUPPORTED_AUTHORITY_STATE_KEY_FILE_VERSIONS = frozenset({1})
AUTHORITY_STATE_KEY_BYTES = 32


class AuthorityStateKeyRecord(BaseModel):
    key_file_version: int = Field(
        default=1,
        ge=1,
    )

    key_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    algorithm: str = "hmac-sha256"

    key_b64: str = Field(
        min_length=1,
    )

    @field_validator("key_b64")
    @classmethod
    def validate_key_material(
        cls,
        value: str,
    ) -> str:
        try:
            raw = base64.b64decode(
                value,
                validate=True,
            )
        except ValueError as exc:
            raise ValueError("Authority-state key material must use strict base64.") from exc

        if len(raw) != AUTHORITY_STATE_KEY_BYTES:
            raise ValueError("Authority-state key material must decode to exactly 32 bytes.")

        return value

    @model_validator(mode="after")
    def validate_record(
        self,
    ) -> AuthorityStateKeyRecord:
        if self.key_file_version not in SUPPORTED_AUTHORITY_STATE_KEY_FILE_VERSIONS:
            raise ValueError(
                "Unsupported authority-state key-file version "
                f"{self.key_file_version}. Supported: "
                f"{sorted(SUPPORTED_AUTHORITY_STATE_KEY_FILE_VERSIONS)}."
            )

        if self.algorithm != "hmac-sha256":
            raise ValueError("Authority-state key algorithm must be hmac-sha256.")

        return self
