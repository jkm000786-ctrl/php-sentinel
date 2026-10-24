from __future__ import annotations

import re
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator

SUPPORTED_SOURCE_REGISTRY_VERSIONS = frozenset({1})

MAX_SOURCE_REGISTRY_SOURCES = 256
MAX_SOURCE_CHANNELS_PER_SOURCE = 128
MAX_SOURCE_ALLOWED_SIGNERS = 128


class IntelligenceSourceChannel(BaseModel):
    channel: str = Field(
        min_length=1,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    enabled: bool = True

    policy_path: str = Field(
        min_length=1,
    )

    manifest_path: str = Field(
        min_length=1,
    )

    minimum_generation: int = Field(
        default=1,
        ge=1,
    )

    @field_validator(
        "policy_path",
        "manifest_path",
    )
    @classmethod
    def validate_relative_path(
        cls,
        value: str,
    ) -> str:
        if value.startswith("/"):
            raise ValueError("Source channel paths must be relative.")

        parts = value.split("/")

        if ".." in parts or "." in parts or "" in parts:
            raise ValueError(
                "Source channel paths must not contain empty, dot, or parent segments."
            )

        parsed = urlsplit(value)

        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("Source channel paths must be plain relative paths.")

        return value


_CANONICAL_SIGNER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class IntelligenceSource(BaseModel):
    source_id: str = Field(
        min_length=1,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )

    enabled: bool = True

    base_url: str = Field(
        min_length=1,
    )

    allowed_signer_ids: list[str] = Field(
        min_length=1,
        max_length=MAX_SOURCE_ALLOWED_SIGNERS,
    )

    channels: list[IntelligenceSourceChannel] = Field(
        min_length=1,
        max_length=MAX_SOURCE_CHANNELS_PER_SOURCE,
    )

    @field_validator("allowed_signer_ids")
    @classmethod
    def validate_allowed_signer_ids(
        cls,
        value: list[str],
    ) -> list[str]:
        for signer_id in value:
            if len(signer_id) > 128 or not _CANONICAL_SIGNER_ID_RE.fullmatch(signer_id):
                raise ValueError("Source allowed signer IDs must use canonical signer identity.")

        return value

    @field_validator("base_url")
    @classmethod
    def validate_base_url(
        cls,
        value: str,
    ) -> str:
        parsed = urlsplit(value)

        if parsed.scheme.lower() != "https":
            raise ValueError("Intelligence source base_url must use HTTPS.")

        if not parsed.hostname:
            raise ValueError("Intelligence source base_url requires a hostname.")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Intelligence source base_url must not contain credentials.")

        if parsed.query or parsed.fragment:
            raise ValueError("Intelligence source base_url must not contain a query or fragment.")

        return value.rstrip("/") + "/"

    @model_validator(mode="after")
    def validate_source(
        self,
    ) -> IntelligenceSource:
        signer_ids = self.allowed_signer_ids

        if len(signer_ids) != len(set(signer_ids)):
            raise ValueError("Source allowed signer IDs must be unique.")

        channel_ids = [item.channel for item in self.channels]

        if len(channel_ids) != len(set(channel_ids)):
            raise ValueError("Source channel names must be unique.")

        return self


class IntelligenceSourceRegistry(BaseModel):
    registry_version: int = 1

    sources: list[IntelligenceSource] = Field(
        default_factory=list,
        max_length=MAX_SOURCE_REGISTRY_SOURCES,
    )

    @model_validator(mode="after")
    def validate_registry(
        self,
    ) -> IntelligenceSourceRegistry:
        if self.registry_version not in SUPPORTED_SOURCE_REGISTRY_VERSIONS:
            raise ValueError(
                "Unsupported source-registry version "
                f"{self.registry_version}. Supported: "
                f"{sorted(SUPPORTED_SOURCE_REGISTRY_VERSIONS)}."
            )

        source_ids = [item.source_id for item in self.sources]

        if len(source_ids) != len(set(source_ids)):
            raise ValueError("Intelligence source IDs must be unique.")

        return self


class IntelligenceSourceSelection(BaseModel):
    source_id: str
    channel: str

    policy_url: str
    manifest_url: str

    allowed_signer_ids: list[str]

    minimum_generation: int = Field(
        ge=1,
    )
