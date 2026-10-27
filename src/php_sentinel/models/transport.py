from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class TransportStopReason(str, Enum):
    COMPLETED = "completed"
    RATE_LIMITED = "rate_limited"
    RETRY_EXHAUSTED = "retry_exhausted"
    REQUEST_BUDGET_EXHAUSTED = "request_budget_exhausted"
    RETRY_AFTER_EXCEEDS_POLICY = "retry_after_exceeds_policy"
    REDIRECT_LIMIT_EXHAUSTED = "redirect_limit_exhausted"
    REDIRECT_TARGET_DENIED = "redirect_target_denied"


class TransportPolicy(BaseModel):
    max_attempts: int = Field(default=2, ge=1, le=5)
    request_budget: int = Field(default=2, ge=1, le=5)
    maximum_redirects: int = Field(default=5, ge=0, le=10)
    allow_cross_host_redirects: bool = False
    retry_statuses: tuple[int, ...] = (429, 503)
    retry_after_enabled: bool = True
    maximum_retry_after_seconds: float = Field(
        default=30.0,
        ge=0.0,
        le=300.0,
    )
    base_backoff_seconds: float = Field(
        default=1.0,
        ge=0.0,
        le=60.0,
    )
    maximum_backoff_seconds: float = Field(
        default=8.0,
        ge=0.0,
        le=120.0,
    )

    @model_validator(mode="after")
    def validate_transport_bounds(self) -> TransportPolicy:
        if self.max_attempts > self.request_budget:
            raise ValueError(
                "max_attempts must not exceed request_budget."
            )

        if self.base_backoff_seconds > self.maximum_backoff_seconds:
            raise ValueError(
                "base_backoff_seconds must not exceed maximum_backoff_seconds."
            )

        if len(set(self.retry_statuses)) != len(self.retry_statuses):
            raise ValueError(
                "retry_statuses must not contain duplicate status codes."
            )

        if any(
            status < 100 or status > 599
            for status in self.retry_statuses
        ):
            raise ValueError(
                "retry_statuses must contain valid HTTP status codes."
            )

        return self


class TransportExecution(BaseModel):
    attempts: int = Field(default=0, ge=0)
    requests_sent: int = Field(default=0, ge=0)
    retries: int = Field(default=0, ge=0)
    budget_exhausted: bool = False
    retry_after_observed: bool = False
    retry_after_honored: bool = False
    retry_after_exceeded_policy: bool = False
    rate_limit_observed: bool = False
    redirect_target_denied: bool = False
    stop_reason: TransportStopReason = TransportStopReason.COMPLETED
    redirect_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_execution_counts(self) -> TransportExecution:
        if self.retries > self.attempts:
            raise ValueError(
                "retries must not exceed attempts."
            )

        if self.attempts > self.requests_sent:
            raise ValueError(
                "attempts must not exceed requests_sent."
            )

        if self.redirect_count > self.requests_sent:
            raise ValueError(
                "redirect_count must not exceed requests_sent."
            )

        return self


class TransportEvidence(BaseModel):
    policy: TransportPolicy = Field(default_factory=TransportPolicy)
    execution: TransportExecution = Field(default_factory=TransportExecution)
