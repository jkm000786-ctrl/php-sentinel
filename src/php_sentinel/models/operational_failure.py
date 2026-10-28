from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from php_sentinel.models.transport import (
    TransportEvidence,
    TransportStopReason,
)

_OPERATIONAL_FAILURE_STOP_REASONS = frozenset(
    {
        TransportStopReason.RESPONSE_BODY_LIMIT_EXCEEDED,
        TransportStopReason.TIMEOUT,
        TransportStopReason.NETWORK_ERROR,
        TransportStopReason.PROTOCOL_ERROR,
        TransportStopReason.TRANSPORT_ERROR,
    }
)


class OperationalFailureEvidence(BaseModel):
    schema_version: Literal[1] = 1
    artifact_type: Literal["operational_failure"] = (
        "operational_failure"
    )
    tool_name: Literal["php-sentinel"] = "php-sentinel"
    tool_version: str = Field(min_length=1)
    target: str = Field(min_length=1)
    failure_reason: TransportStopReason
    complete_response_available: Literal[False] = False
    assessment_available: Literal[False] = False
    transport: TransportEvidence

    @model_validator(mode="after")
    def validate_failure_authority(
        self,
    ) -> OperationalFailureEvidence:
        transport_reason = (
            self.transport.execution.stop_reason
        )

        if self.failure_reason == TransportStopReason.COMPLETED:
            raise ValueError(
                "Operational failure evidence cannot use "
                "a completed transport stop reason."
            )

        if (
            self.failure_reason
            not in _OPERATIONAL_FAILURE_STOP_REASONS
        ):
            raise ValueError(
                "Operational failure evidence requires "
                "a no-complete-response transport stop reason."
            )

        if self.failure_reason != transport_reason:
            raise ValueError(
                "Operational failure reason must match "
                "transport execution stop reason."
            )

        return self
