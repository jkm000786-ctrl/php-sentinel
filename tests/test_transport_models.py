from __future__ import annotations

import pytest
from pydantic import ValidationError

from php_sentinel.models.transport import (
    TransportEvidence,
    TransportExecution,
    TransportPolicy,
    TransportStopReason,
)


def test_default_transport_policy_is_bounded_and_conservative():
    policy = TransportPolicy()

    assert policy.max_attempts == 2
    assert policy.request_budget == 2
    assert policy.maximum_redirects == 5
    assert policy.allow_cross_host_redirects is False
    assert policy.retry_statuses == (429, 503)
    assert policy.retry_after_enabled is True
    assert policy.maximum_retry_after_seconds == 30.0
    assert policy.base_backoff_seconds == 1.0
    assert policy.maximum_backoff_seconds == 8.0


def test_transport_policy_rejects_attempts_above_budget():
    with pytest.raises(
        ValidationError,
        match="max_attempts must not exceed request_budget",
    ):
        TransportPolicy(
            max_attempts=3,
            request_budget=2,
        )


def test_transport_policy_rejects_inverted_backoff_bounds():
    with pytest.raises(
        ValidationError,
        match="base_backoff_seconds must not exceed maximum_backoff_seconds",
    ):
        TransportPolicy(
            base_backoff_seconds=10.0,
            maximum_backoff_seconds=5.0,
        )


def test_transport_policy_rejects_duplicate_retry_statuses():
    with pytest.raises(
        ValidationError,
        match="retry_statuses must not contain duplicate status codes",
    ):
        TransportPolicy(
            retry_statuses=(429, 429),
        )


def test_transport_execution_rejects_retries_above_attempts():
    with pytest.raises(
        ValidationError,
        match="retries must not exceed attempts",
    ):
        TransportExecution(
            attempts=1,
            requests_sent=1,
            retries=2,
        )


def test_transport_evidence_serializes_safe_execution_summary():
    evidence = TransportEvidence(
        execution=TransportExecution(
            attempts=2,
            requests_sent=3,
            retries=1,
            rate_limit_observed=True,
            retry_after_observed=True,
            retry_after_honored=True,
            stop_reason=TransportStopReason.COMPLETED,
            redirect_count=1,
        )
    )

    payload = evidence.model_dump(mode="json")

    assert payload["policy"]["request_budget"] == 2
    assert payload["execution"]["attempts"] == 2
    assert payload["execution"]["requests_sent"] == 3
    assert payload["execution"]["retries"] == 1
    assert payload["execution"]["rate_limit_observed"] is True
    assert payload["execution"]["retry_after_honored"] is True
    assert payload["execution"]["stop_reason"] == "completed"
    assert payload["execution"]["redirect_count"] == 1


def test_transport_execution_rejects_attempts_above_requests_sent():
    with pytest.raises(
        ValidationError,
        match="attempts must not exceed requests_sent",
    ):
        TransportExecution(
            attempts=2,
            requests_sent=1,
        )


def test_transport_execution_rejects_redirects_above_requests_sent():
    with pytest.raises(
        ValidationError,
        match="redirect_count must not exceed requests_sent",
    ):
        TransportExecution(
            attempts=1,
            requests_sent=1,
            redirect_count=2,
        )


def test_redirect_denial_has_explicit_stop_reason():
    execution = TransportExecution(
        attempts=1,
        requests_sent=1,
        redirect_target_denied=True,
        stop_reason=TransportStopReason.REDIRECT_TARGET_DENIED,
    )

    assert execution.redirect_target_denied is True
    assert (
        execution.stop_reason
        == TransportStopReason.REDIRECT_TARGET_DENIED
    )
