from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from php_sentinel.models.edge import (
    ApplicationReachability,
    EdgeAssessment,
    EdgeProvider,
    EdgeResponseClass,
)


class DifferentialEvidenceAuthority(str, Enum):
    AUTHORIZED_LOCAL_LAB = "authorized_local_lab"


class WAFDifferentialEvidence(BaseModel):
    """Trusted negative reachability evidence from an authorized WAF differential."""

    model_config = ConfigDict(frozen=True)

    authority: DifferentialEvidenceAuthority = (
        DifferentialEvidenceAuthority.AUTHORIZED_LOCAL_LAB
    )
    provider: EdgeProvider = EdgeProvider.UNKNOWN
    direct_application_reached: Literal[True] = True
    protected_application_reached: Literal[False] = False
    waf_interrupted: Literal[True] = True
    protected_http_status: int = Field(ge=100, le=599)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rationale: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_waf_authority(self) -> WAFDifferentialEvidence:
        if self.provider == EdgeProvider.NONE:
            raise ValueError(
                "Differential WAF evidence cannot use provider=none."
            )
        return self


class EdgeAuthorityDecision(BaseModel):
    """Resolved edge authority without mutating the passive observation."""

    model_config = ConfigDict(frozen=True)

    passive: EdgeAssessment
    effective_response_class: EdgeResponseClass
    effective_application_reachability: ApplicationReachability
    waf_interception_established: bool = False
    constrained_by_differential: bool = False
    differential_evidence: WAFDifferentialEvidence | None = None
    rationale: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_resolution(self) -> EdgeAuthorityDecision:
        evidence = self.differential_evidence

        if evidence is None:
            if self.constrained_by_differential:
                raise ValueError(
                    "Edge authority cannot be differential-constrained "
                    "without differential evidence."
                )

            if self.effective_response_class != self.passive.response_class:
                raise ValueError(
                    "Without differential evidence, effective response class "
                    "must equal passive response class."
                )

            if (
                self.effective_application_reachability
                != self.passive.application_reachability
            ):
                raise ValueError(
                    "Without differential evidence, effective reachability "
                    "must equal passive reachability."
                )

            passive_interception = (
                self.passive.waf_detected
                and self.passive.response_class == EdgeResponseClass.WAF_BLOCK
                and self.passive.application_reachability
                == ApplicationReachability.NOT_REACHED
            )

            if self.waf_interception_established != passive_interception:
                raise ValueError(
                    "Without differential evidence, WAF interception authority "
                    "must match the passive explicit-WAF state."
                )

            return self

        if not self.constrained_by_differential:
            raise ValueError(
                "Differential evidence requires "
                "constrained_by_differential=true."
            )

        if not self.waf_interception_established:
            raise ValueError(
                "Differential WAF evidence must establish WAF interception."
            )

        if self.effective_response_class != EdgeResponseClass.WAF_BLOCK:
            raise ValueError(
                "Differential WAF evidence must resolve to "
                "response_class=waf_block."
            )

        if (
            self.effective_application_reachability
            != ApplicationReachability.NOT_REACHED
        ):
            raise ValueError(
                "Differential WAF evidence may only constrain reachability "
                "to not_reached."
            )

        return self
