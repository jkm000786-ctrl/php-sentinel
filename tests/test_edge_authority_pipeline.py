from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from php_sentinel.assessment.pipeline import run_unified_assessment
from php_sentinel.models.edge import EdgeProvider
from php_sentinel.models.edge_authority import WAFDifferentialEvidence

LOOPBACK_TARGET = "http://127.0.0.1/"


def _blocked_response(
    *,
    request_url: str = LOOPBACK_TARGET,
    status_code: int = 403,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        request=httpx.Request(
            "GET",
            request_url,
        ),
        headers={
            "Server": "nginx",
        },
        text="403 Forbidden",
    )


def _evidence(
    *,
    status_code: int = 403,
    digest: str = "c" * 64,
) -> WAFDifferentialEvidence:
    return WAFDifferentialEvidence(
        provider=EdgeProvider.MODSECURITY,
        protected_http_status=status_code,
        evidence_sha256=digest,
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_generic_403_without_differential_preserves_passive_state(
    mock_fetch,
):
    mock_fetch.return_value = _blocked_response()

    report = run_unified_assessment(
        LOOPBACK_TARGET,
    )

    assert (
        report.edge.response_class.value
        == "application_response"
    )
    assert (
        report.edge.application_reachability.value
        == "probable"
    )
    assert report.edge_authority is None


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_authorized_local_differential_constrains_pipeline(
    mock_fetch,
):
    mock_fetch.return_value = _blocked_response()

    report = run_unified_assessment(
        LOOPBACK_TARGET,
        differential_evidence=_evidence(),
    )

    assert (
        report.edge.response_class.value
        == "application_response"
    )
    assert (
        report.edge.application_reachability.value
        == "probable"
    )

    authority = report.edge_authority

    assert authority is not None
    assert (
        authority.effective_response_class.value
        == "waf_block"
    )
    assert (
        authority.effective_application_reachability.value
        == "not_reached"
    )
    assert authority.waf_interception_established is True
    assert authority.constrained_by_differential is True

    assert report.assessment.status.value == "inconclusive"
    assert report.assessment.php_detected is False
    assert report.assessment.php_version is None
    assert report.assessment.php_confidence == 0.0
    assert report.assessment.applicable_cves == []

    assert all(
        item.status.value == "inconclusive"
        for item in report.cve_decisions.decisions
    )

    assert all(
        item.state.value == "inconclusive"
        for item in report.findings
    )

    assert all(
        (
            "Effective application reachability: "
            "not_reached"
        )
        in finding.evidence
        for finding in report.findings
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_authorized_local_differential_rejects_public_target(
    mock_fetch,
):
    target = "https://example.test/"

    mock_fetch.return_value = _blocked_response(
        request_url=target,
    )

    with pytest.raises(
        ValueError,
        match="loopback",
    ):
        run_unified_assessment(
            target,
            differential_evidence=_evidence(),
        )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_differential_status_must_match_observed_response(
    mock_fetch,
):
    mock_fetch.return_value = _blocked_response(
        status_code=403,
    )

    with pytest.raises(
        ValueError,
        match="HTTP status",
    ):
        run_unified_assessment(
            LOOPBACK_TARGET,
            differential_evidence=_evidence(
                status_code=429,
            ),
        )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_local_differential_rejects_non_loopback_final_url(
    mock_fetch,
):
    mock_fetch.return_value = _blocked_response(
        request_url="https://example.test/",
    )

    with pytest.raises(
        ValueError,
        match="loopback",
    ):
        run_unified_assessment(
            LOOPBACK_TARGET,
            differential_evidence=_evidence(),
        )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_differential_changes_canonical_and_target_identity(
    mock_fetch,
):
    mock_fetch.side_effect = [
        _blocked_response(),
        _blocked_response(),
    ]

    passive = run_unified_assessment(
        LOOPBACK_TARGET,
    )

    constrained = run_unified_assessment(
        LOOPBACK_TARGET,
        differential_evidence=_evidence(
            digest="d" * 64,
        ),
    )

    assert (
        passive.provenance.canonical_sha256
        != constrained.provenance.canonical_sha256
    )

    assert (
        passive.provenance.target_identity_sha256
        != constrained.provenance.target_identity_sha256
    )

@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_differential_artifact_digest_changes_canonical_not_target_identity(
    mock_fetch,
):
    mock_fetch.side_effect = [
        _blocked_response(),
        _blocked_response(),
    ]

    first = run_unified_assessment(
        LOOPBACK_TARGET,
        differential_evidence=_evidence(
            digest="d" * 64,
        ),
    )

    second = run_unified_assessment(
        LOOPBACK_TARGET,
        differential_evidence=_evidence(
            digest="e" * 64,
        ),
    )

    first_authority = first.edge_authority
    second_authority = second.edge_authority

    assert first_authority is not None
    assert second_authority is not None

    assert (
        first_authority.effective_response_class
        == second_authority.effective_response_class
    )

    assert (
        first_authority.effective_application_reachability
        == second_authority.effective_application_reachability
    )

    assert (
        first_authority.waf_interception_established
        == second_authority.waf_interception_established
    )

    assert (
        first_authority.constrained_by_differential
        == second_authority.constrained_by_differential
    )

    assert (
        first.provenance.canonical_sha256
        != second.provenance.canonical_sha256
    )

    assert (
        first.provenance.target_identity_sha256
        == second.provenance.target_identity_sha256
    )

    assert (
        first.provenance.differential_evidence_sha256
        == "d" * 64
    )

    assert (
        second.provenance.differential_evidence_sha256
        == "e" * 64
    )
