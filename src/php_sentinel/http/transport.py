from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx

from php_sentinel.models.transport import (
    TransportPolicy,
    TransportStopReason,
)


@dataclass(frozen=True)
class RetryDecision:
    should_retry: bool
    delay_seconds: float
    stop_reason: TransportStopReason
    retry_after_observed: bool = False
    retry_after_honored: bool = False
    retry_after_exceeded_policy: bool = False
    rate_limit_observed: bool = False


def _parse_retry_after_seconds(
    value: str | None,
    *,
    now: datetime | None = None,
) -> float | None:
    if value is None:
        return None

    stripped = value.strip()

    if not stripped:
        return None

    try:
        seconds = int(stripped)
    except ValueError:
        seconds = None

    if seconds is not None:
        if seconds < 0:
            return None

        return float(seconds)

    try:
        retry_at = parsedate_to_datetime(stripped)
    except (TypeError, ValueError, OverflowError):
        return None

    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=UTC)

    current = now or datetime.now(UTC)

    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)

    delay = (retry_at - current).total_seconds()

    if delay < 0:
        return 0.0

    return delay


def decide_retry(
    response: httpx.Response,
    *,
    policy: TransportPolicy,
    attempts: int,
    retries: int,
    requests_sent: int | None = None,
    now: datetime | None = None,
) -> RetryDecision:
    status = response.status_code
    rate_limited = status == 429

    if status not in policy.retry_statuses:
        return RetryDecision(
            should_retry=False,
            delay_seconds=0.0,
            stop_reason=TransportStopReason.COMPLETED,
            rate_limit_observed=rate_limited,
        )

    budget_consumed = (
        attempts
        if requests_sent is None
        else requests_sent
    )

    if budget_consumed >= policy.request_budget:
        return RetryDecision(
            should_retry=False,
            delay_seconds=0.0,
            stop_reason=TransportStopReason.REQUEST_BUDGET_EXHAUSTED,
            rate_limit_observed=rate_limited,
        )

    if attempts >= policy.max_attempts:
        return RetryDecision(
            should_retry=False,
            delay_seconds=0.0,
            stop_reason=TransportStopReason.RETRY_EXHAUSTED,
            rate_limit_observed=rate_limited,
        )

    retry_after_header = response.headers.get("retry-after")
    retry_after = (
        _parse_retry_after_seconds(
            retry_after_header,
            now=now,
        )
        if policy.retry_after_enabled
        else None
    )

    retry_after_observed = retry_after_header is not None

    if retry_after is not None:
        if retry_after > policy.maximum_retry_after_seconds:
            return RetryDecision(
                should_retry=False,
                delay_seconds=0.0,
                stop_reason=(
                    TransportStopReason.RETRY_AFTER_EXCEEDS_POLICY
                ),
                retry_after_observed=retry_after_observed,
                retry_after_exceeded_policy=True,
                rate_limit_observed=rate_limited,
            )

        effective_delay = retry_after

        if rate_limited:
            effective_delay = max(
                effective_delay,
                policy.base_backoff_seconds,
            )

        return RetryDecision(
            should_retry=True,
            delay_seconds=effective_delay,
            stop_reason=TransportStopReason.COMPLETED,
            retry_after_observed=retry_after_observed,
            retry_after_honored=True,
            rate_limit_observed=rate_limited,
        )

    delay = min(
        policy.base_backoff_seconds * (2**retries),
        policy.maximum_backoff_seconds,
    )

    return RetryDecision(
        should_retry=True,
        delay_seconds=delay,
        stop_reason=TransportStopReason.COMPLETED,
        retry_after_observed=retry_after_observed,
        rate_limit_observed=rate_limited,
    )
