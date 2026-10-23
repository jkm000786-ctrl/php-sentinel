from __future__ import annotations

from datetime import date
from typing import Literal

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field, field_validator, model_validator

PriorityName = Literal[
    "critical",
    "high",
    "elevated",
    "none",
    "unknown",
]


class IntelligenceSource(BaseModel):
    publisher: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    reference: str = Field(min_length=1)


class SAPIPriorityPolicy(BaseModel):
    critical: list[str] = Field(default_factory=list)
    high: list[str] = Field(default_factory=list)
    unknown_priority: PriorityName = "elevated"
    other_priority: PriorityName = "unknown"

    @model_validator(mode="after")
    def validate_unique_sapis(self) -> SAPIPriorityPolicy:
        overlap = set(self.critical) & set(self.high)

        if overlap:
            raise ValueError(
                "SAPI values cannot exist in both critical and high groups: "
                + ", ".join(sorted(overlap))
            )

        return self


class IntelligenceGuidance(BaseModel):
    upgrade_template: str = Field(min_length=1)
    supported_branch_upgrade: str = Field(min_length=1)
    patched_upstream: str = Field(min_length=1)
    patched_vendor: str = Field(min_length=1)


class CVEPolicy(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    severity: Literal[
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    ]
    affected_sapis: list[str] = Field(default_factory=list)
    temporary_mitigations: list[str] = Field(default_factory=list)


class IntelligencePolicy(BaseModel):
    schema_version: int = Field(ge=1)
    policy_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    product: str = Field(min_length=1)
    published_date: date
    source: IntelligenceSource
    fixed_versions: dict[str, str]
    sapi_priority: SAPIPriorityPolicy
    guidance: IntelligenceGuidance
    cves: list[CVEPolicy] = Field(min_length=1)
    notes: list[str] = Field(default_factory=list)

    @field_validator("fixed_versions")
    @classmethod
    def validate_fixed_versions(
        cls,
        value: dict[str, str],
    ) -> dict[str, str]:
        if not value:
            raise ValueError("At least one fixed PHP branch must be modeled.")

        for branch, raw_version in value.items():
            branch_parts = branch.split(".")

            if len(branch_parts) != 2 or not all(part.isdigit() for part in branch_parts):
                raise ValueError(f"Invalid PHP branch key: {branch!r}")

            expected_branch = tuple(int(part) for part in branch_parts)

            try:
                parsed = Version(raw_version)
            except InvalidVersion as exc:
                raise ValueError(f"Invalid fixed version: {raw_version!r}") from exc

            if parsed.release[:2] != expected_branch:
                raise ValueError(
                    f"Fixed version {raw_version!r} does not belong to branch {branch!r}."
                )

        return value

    @model_validator(mode="after")
    def validate_unique_cves(
        self,
    ) -> IntelligencePolicy:
        ids = [item.cve_id for item in self.cves]

        if len(ids) != len(set(ids)):
            raise ValueError("CVE identifiers must be unique.")

        return self
