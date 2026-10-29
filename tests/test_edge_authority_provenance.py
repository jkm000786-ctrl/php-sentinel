from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from php_sentinel.assessment.edge_authority import (
    resolve_edge_authority,
)
from php_sentinel.assessment.pipeline import (
    run_unified_assessment,
)
from php_sentinel.evidence.provenance import (
    build_provenance,
)
from php_sentinel.models.edge import (
    ApplicationReachability,
    EdgeAssessment,
    EdgeProvider,
    EdgeResponseClass,
)
from php_sentinel.models.edge_authority import (
    WAFDifferentialEvidence,
)

TARGET = "http://127.0.0.1/"
DIGEST = "a" * 64


def _passive() -> EdgeAssessment:
    return EdgeAssessment(
        edge_detected=False,
        waf_detected=False,
        provider=EdgeProvider.NONE,
        response_class=EdgeResponseClass.APPLICATION_RESPONSE,
        application_reachability=ApplicationReachability.PROBABLE,
    )


def _evidence() -> WAFDifferentialEvidence:
    return WAFDifferentialEvidence(
        provider=EdgeProvider.MODSECURITY,
        protected_http_status=403,
        evidence_sha256=DIGEST,
    )


def _blocked() -> httpx.Response:
    return httpx.Response(
        403,
        request=httpx.Request(
            "GET",
            TARGET,
        ),
        headers={
            "Server": "nginx",
        },
        text="403 Forbidden",
    )


def test_provenance_without_authority_keeps_effective_fields_empty():
    provenance = build_provenance(
        canonical_payload={
            "target": "passive",
        },
        target_identity_payload={
            "target": "passive",
        },
        edge_assessment=_passive(),
    )

    assert provenance.edge_response_class == "application_response"
    assert provenance.application_reachability == "probable"

    assert provenance.effective_edge_response_class is None
    assert provenance.effective_application_reachability is None
    assert provenance.waf_interception_established is None
    assert (
        provenance.edge_authority_constrained_by_differential
        is None
    )
    assert provenance.differential_evidence_authority is None
    assert provenance.differential_edge_provider is None
    assert provenance.differential_protected_http_status is None
    assert provenance.differential_evidence_sha256 is None


def test_provenance_binds_resolved_differential_authority():
    passive = _passive()
    evidence = _evidence()

    authority = resolve_edge_authority(
        passive,
        differential_evidence=evidence,
    )

    provenance = build_provenance(
        canonical_payload={
            "target": "constrained",
        },
        target_identity_payload={
            "target": "constrained",
        },
        edge_assessment=passive,
        edge_authority=authority,
    )

    assert provenance.edge_response_class == "application_response"
    assert provenance.application_reachability == "probable"

    assert provenance.effective_edge_response_class == "waf_block"
    assert (
        provenance.effective_application_reachability
        == "not_reached"
    )
    assert provenance.waf_interception_established is True
    assert (
        provenance.edge_authority_constrained_by_differential
        is True
    )
    assert (
        provenance.differential_evidence_authority
        == "authorized_local_lab"
    )
    assert provenance.differential_edge_provider == "modsecurity"
    assert provenance.differential_protected_http_status == 403
    assert provenance.differential_evidence_sha256 == DIGEST


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_pipeline_provenance_matches_report_authority(
    mock_fetch,
):
    mock_fetch.return_value = _blocked()

    report = run_unified_assessment(
        TARGET,
        differential_evidence=_evidence(),
    )

    authority = report.edge_authority

    assert authority is not None

    assert (
        report.provenance.effective_edge_response_class
        == authority.effective_response_class.value
    )
    assert (
        report.provenance.effective_application_reachability
        == authority.effective_application_reachability.value
    )
    assert (
        report.provenance.waf_interception_established
        == authority.waf_interception_established
    )
    assert (
        report.provenance.edge_authority_constrained_by_differential
        == authority.constrained_by_differential
    )
    assert (
        report.provenance.differential_evidence_sha256
        == DIGEST
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_normal_pipeline_does_not_invent_effective_authority(
    mock_fetch,
):
    mock_fetch.return_value = _blocked()

    report = run_unified_assessment(
        TARGET,
    )

    assert report.edge_authority is None

    assert (
        report.provenance.effective_edge_response_class
        is None
    )
    assert (
        report.provenance.effective_application_reachability
        is None
    )
    assert (
        report.provenance.differential_evidence_sha256
        is None
    )

def test_provenance_rejects_authority_without_passive_edge():
    authority = resolve_edge_authority(
        _passive(),
        differential_evidence=_evidence(),
    )

    with pytest.raises(
        ValueError,
        match="requires the passive edge assessment",
    ):
        build_provenance(
            canonical_payload={
                "target": "missing-passive",
            },
            target_identity_payload={
                "target": "missing-passive",
            },
            edge_authority=authority,
        )


def test_provenance_rejects_authority_passive_mismatch():
    authority = resolve_edge_authority(
        _passive(),
        differential_evidence=_evidence(),
    )

    different_passive = EdgeAssessment(
        edge_detected=False,
        waf_detected=False,
        provider=EdgeProvider.NONE,
        response_class=EdgeResponseClass.EDGE_RESPONSE,
        application_reachability=ApplicationReachability.UNKNOWN,
    )

    with pytest.raises(
        ValueError,
        match="does not match",
    ):
        build_provenance(
            canonical_payload={
                "target": "mismatch",
            },
            target_identity_payload={
                "target": "mismatch",
            },
            edge_assessment=different_passive,
            edge_authority=authority,
        )
