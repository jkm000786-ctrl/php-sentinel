from __future__ import annotations

from datetime import UTC, datetime

import httpx

from php_sentinel.http.transport import (
    _parse_retry_after_seconds,
    decide_retry,
)
from php_sentinel.models.transport import (
    TransportPolicy,
    TransportStopReason,
)


def response(
    status: int,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status,
        headers=headers or {},
        request=httpx.Request(
            "GET",
            "https://example.test/",
        ),
    )


def test_non_retry_status_completes_without_retry():
    decision = decide_retry(
        response(200),
        policy=TransportPolicy(),
        attempts=1,
        retries=0,
    )

    assert decision.should_retry is False
    assert decision.delay_seconds == 0.0
    assert decision.stop_reason == TransportStopReason.COMPLETED


def test_429_never_increases_request_rate_and_uses_backoff():
    decision = decide_retry(
        response(429),
        policy=TransportPolicy(),
        attempts=1,
        retries=0,
    )

    assert decision.should_retry is True
    assert decision.delay_seconds == 1.0
    assert decision.rate_limit_observed is True


def test_retry_after_delta_seconds_is_honored_when_within_policy():
    decision = decide_retry(
        response(
            429,
            headers={"Retry-After": "10"},
        ),
        policy=TransportPolicy(),
        attempts=1,
        retries=0,
    )

    assert decision.should_retry is True
    assert decision.delay_seconds == 10.0
    assert decision.retry_after_observed is True
    assert decision.retry_after_honored is True


def test_retry_after_above_policy_fails_closed():
    decision = decide_retry(
        response(
            429,
            headers={"Retry-After": "120"},
        ),
        policy=TransportPolicy(
            maximum_retry_after_seconds=30.0,
        ),
        attempts=1,
        retries=0,
    )

    assert decision.should_retry is False
    assert (
        decision.stop_reason
        == TransportStopReason.RETRY_AFTER_EXCEEDS_POLICY
    )
    assert decision.retry_after_exceeded_policy is True
    assert decision.rate_limit_observed is True


def test_request_budget_prevents_additional_retry():
    decision = decide_retry(
        response(503),
        policy=TransportPolicy(
            max_attempts=2,
            request_budget=2,
        ),
        attempts=2,
        retries=1,
    )

    assert decision.should_retry is False
    assert (
        decision.stop_reason
        == TransportStopReason.REQUEST_BUDGET_EXHAUSTED
    )


def test_exponential_backoff_is_bounded():
    policy = TransportPolicy(
        max_attempts=5,
        request_budget=5,
        base_backoff_seconds=2.0,
        maximum_backoff_seconds=5.0,
    )

    decision = decide_retry(
        response(503),
        policy=policy,
        attempts=4,
        retries=3,
    )

    assert decision.should_retry is True
    assert decision.delay_seconds == 5.0


def test_retry_after_http_date_is_supported_deterministically():
    now = datetime(
        2026,
        10,
        26,
        12,
        0,
        0,
        tzinfo=UTC,
    )

    parsed = _parse_retry_after_seconds(
        "Mon, 26 Oct 2026 12:00:15 GMT",
        now=now,
    )

    assert parsed == 15.0


def test_invalid_retry_after_falls_back_to_backoff():
    decision = decide_retry(
        response(
            429,
            headers={"Retry-After": "invalid"},
        ),
        policy=TransportPolicy(),
        attempts=1,
        retries=0,
    )

    assert decision.should_retry is True
    assert decision.delay_seconds == 1.0
    assert decision.retry_after_observed is True
    assert decision.retry_after_honored is False


def test_disabled_retry_after_uses_policy_backoff():
    decision = decide_retry(
        response(
            429,
            headers={"Retry-After": "10"},
        ),
        policy=TransportPolicy(
            retry_after_enabled=False,
        ),
        attempts=1,
        retries=0,
    )

    assert decision.should_retry is True
    assert decision.delay_seconds == 1.0
    assert decision.retry_after_observed is True
    assert decision.retry_after_honored is False


def test_429_retry_after_zero_still_uses_minimum_backoff():
    decision = decide_retry(
        response(
            429,
            headers={"Retry-After": "0"},
        ),
        policy=TransportPolicy(
            base_backoff_seconds=2.0,
        ),
        attempts=1,
        retries=0,
    )

    assert decision.should_retry is True
    assert decision.delay_seconds == 2.0
    assert decision.retry_after_observed is True
    assert decision.retry_after_honored is True
    assert decision.rate_limit_observed is True


def test_non_rate_limit_retry_after_zero_may_be_honored_directly():
    decision = decide_retry(
        response(
            503,
            headers={"Retry-After": "0"},
        ),
        policy=TransportPolicy(
            base_backoff_seconds=2.0,
        ),
        attempts=1,
        retries=0,
    )

    assert decision.should_retry is True
    assert decision.delay_seconds == 0.0
    assert decision.retry_after_honored is True
    assert decision.rate_limit_observed is False
