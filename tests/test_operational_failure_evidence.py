from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from php_sentinel import __version__
from php_sentinel.evidence.operational_failure import (
    build_operational_failure_evidence,
)
from php_sentinel.evidence.writer import write_json_evidence
from php_sentinel.models.operational_failure import (
    OperationalFailureEvidence,
)
from php_sentinel.models.transport import (
    TransportEvidence,
    TransportExecution,
    TransportStopReason,
)


def make_transport(
    reason: TransportStopReason,
) -> TransportEvidence:
    return TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=reason,
        )
    )


def test_operational_failure_is_response_free():
    artifact = build_operational_failure_evidence(
        target="https://example.test/",
        transport=make_transport(
            TransportStopReason.RESPONSE_BODY_LIMIT_EXCEEDED
        ),
    )

    payload = artifact.model_dump(mode="json")

    assert payload["schema_version"] == 1
    assert payload["artifact_type"] == "operational_failure"
    assert payload["tool_name"] == "php-sentinel"
    assert payload["tool_version"] == __version__
    assert payload["target"] == "https://example.test/"
    assert (
        payload["failure_reason"]
        == "response_body_limit_exceeded"
    )
    assert payload["complete_response_available"] is False
    assert payload["assessment_available"] is False

    serialized = json.dumps(
        payload,
        sort_keys=True,
    )

    assert "generated_at" not in serialized
    assert "status_code" not in serialized
    assert "body_sha256" not in serialized
    assert "php_detected" not in serialized
    assert "cve_decisions" not in serialized
    assert "findings" not in serialized


def test_operational_failure_rejects_completed_transport():
    with pytest.raises(
        ValidationError,
        match="cannot use a completed transport stop reason",
    ):
        OperationalFailureEvidence(
            tool_version=__version__,
            target="https://example.test/",
            failure_reason=TransportStopReason.COMPLETED,
            transport=make_transport(
                TransportStopReason.COMPLETED
            ),
        )


def test_operational_failure_rejects_reason_mismatch():
    with pytest.raises(
        ValidationError,
        match="must match transport execution stop reason",
    ):
        OperationalFailureEvidence(
            tool_version=__version__,
            target="https://example.test/",
            failure_reason=TransportStopReason.TIMEOUT,
            transport=make_transport(
                TransportStopReason.NETWORK_ERROR
            ),
        )


@pytest.mark.parametrize(
    "reason",
    [
        TransportStopReason.RATE_LIMITED,
        TransportStopReason.RETRY_EXHAUSTED,
        TransportStopReason.REQUEST_BUDGET_EXHAUSTED,
        TransportStopReason.RETRY_AFTER_EXCEEDS_POLICY,
        TransportStopReason.REDIRECT_LIMIT_EXHAUSTED,
        TransportStopReason.REDIRECT_TARGET_DENIED,
    ],
)
def test_response_bearing_stop_reasons_are_not_operational_failures(
    reason,
):
    with pytest.raises(
        ValidationError,
        match="requires a no-complete-response transport stop reason",
    ):
        OperationalFailureEvidence(
            tool_version=__version__,
            target="https://example.test/",
            failure_reason=reason,
            transport=make_transport(reason),
        )


def test_operational_failure_requires_nonempty_identity():
    transport = make_transport(
        TransportStopReason.TIMEOUT
    )

    with pytest.raises(ValidationError):
        OperationalFailureEvidence(
            tool_version="",
            target="https://example.test/",
            failure_reason=TransportStopReason.TIMEOUT,
            transport=transport,
        )

    with pytest.raises(ValidationError):
        OperationalFailureEvidence(
            tool_version=__version__,
            target="",
            failure_reason=TransportStopReason.TIMEOUT,
            transport=transport,
        )


def test_operational_failure_serialization_is_deterministic(
    tmp_path,
):
    artifact = build_operational_failure_evidence(
        target="https://example.test/",
        transport=make_transport(
            TransportStopReason.TIMEOUT
        ),
    )

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    write_json_evidence(
        artifact,
        first,
    )

    write_json_evidence(
        artifact,
        second,
    )

    assert first.read_bytes() == second.read_bytes()
