from unittest.mock import patch

import httpx
import pytest

from php_sentinel.assessment.consistency import (
    CrossLayerConsistencyError,
    validate_cross_layer_consistency,
)
from php_sentinel.assessment.exposure import assess_response
from php_sentinel.assessment.finding_engine import build_findings
from php_sentinel.assessment.pipeline import run_unified_assessment
from php_sentinel.intelligence.cve_decision_engine import decide_cves
from php_sentinel.intelligence.repository import default_policy
from php_sentinel.models.assessment import AssessmentStatus
from php_sentinel.models.finding import FindingState


def _components():
    policy = default_policy()
    response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://example.test/"),
        headers={
            "Server": "Apache/2.4",
            "X-Powered-By": "PHP/8.5.11",
        },
        text="reference",
    )
    assessment = assess_response(
        "https://example.test/",
        response,
        policy=policy,
    )
    cve_report = decide_cves(
        php_detected=assessment.php_detected,
        php_version=assessment.php_version,
        sapi_hypothesis=assessment.fingerprint.sapi.value,
        policy=policy,
    )
    findings = build_findings(
        target=assessment.target,
        assessment=assessment,
        cve_report=cve_report,
    )
    return assessment, cve_report, findings


def test_consistency_validator_accepts_canonical_layers():
    assessment, cve_report, findings = _components()

    validate_cross_layer_consistency(
        assessment=assessment,
        cve_report=cve_report,
        findings=findings,
    )


def test_consistency_validator_rejects_status_contradiction():
    assessment, cve_report, findings = _components()
    contradictory = assessment.model_copy(
        update={"status": AssessmentStatus.PATCHED_UPSTREAM}
    )

    with pytest.raises(
        CrossLayerConsistencyError,
        match="status does not match",
    ):
        validate_cross_layer_consistency(
            assessment=contradictory,
            cve_report=cve_report,
            findings=findings,
        )


def test_consistency_validator_rejects_priority_contradiction():
    assessment, cve_report, findings = _components()
    contradictory = assessment.model_copy(update={"exposure_priority": "high"})

    with pytest.raises(
        CrossLayerConsistencyError,
        match="exposure priority does not match",
    ):
        validate_cross_layer_consistency(
            assessment=contradictory,
            cve_report=cve_report,
            findings=findings,
        )


def test_consistency_validator_rejects_finding_state_contradiction():
    assessment, cve_report, findings = _components()
    contradictory = list(findings)
    contradictory[0] = contradictory[0].model_copy(
        update={"state": FindingState.PATCHED}
    )

    with pytest.raises(
        CrossLayerConsistencyError,
        match="Finding state mismatch",
    ):
        validate_cross_layer_consistency(
            assessment=assessment,
            cve_report=cve_report,
            findings=contradictory,
        )


@patch("php_sentinel.assessment.pipeline.build_provenance")
@patch("php_sentinel.assessment.pipeline.build_findings", return_value=[])
@patch("php_sentinel.assessment.pipeline.fetch")
def test_pipeline_rejects_contradiction_before_provenance(
    mock_fetch,
    _mock_findings,
    mock_build_provenance,
):
    mock_fetch.return_value = httpx.Response(
        200,
        request=httpx.Request("GET", "http://127.0.0.1/"),
        headers={
            "Server": "Apache/2.4",
            "X-Powered-By": "PHP/8.5.11",
        },
        text="reference",
    )

    with pytest.raises(
        CrossLayerConsistencyError,
        match="Finding CVE set",
    ):
        run_unified_assessment("http://127.0.0.1/")

    mock_build_provenance.assert_not_called()



@pytest.mark.parametrize(
    ("headers", "vendor", "backport_status", "expected_status"),
    [
        ({"Server": "nginx"}, None, None, "not_php"),
        (
            {"Server": "Apache/2.4", "X-Powered-By": "PHP/8.5.12"},
            None,
            None,
            "patched_upstream",
        ),
        (
            {"Server": "Apache/2.4", "X-Powered-By": "PHP/8.5.11"},
            None,
            None,
            "needs_vendor_evidence",
        ),
        (
            {"Server": "Apache/2.4", "X-Powered-By": "PHP/8.5.11"},
            "ubuntu",
            "confirmed_fixed",
            "patched_vendor",
        ),
        (
            {"Server": "Apache/2.4", "X-Powered-By": "PHP/8.5.11"},
            "upstream",
            "unknown",
            "potentially_affected",
        ),
        (
            {"Server": "Apache/2.4", "X-Powered-By": "PHP"},
            None,
            None,
            "inconclusive",
        ),
    ],
)
def test_consistency_validator_accepts_all_terminal_states(
    headers,
    vendor,
    backport_status,
    expected_status,
):
    from php_sentinel.models.vendor import (
        BackportStatus,
        VendorEvidence,
        VendorFamily,
    )

    policy = default_policy()

    evidence = None
    if vendor is not None:
        evidence = VendorEvidence(
            vendor=VendorFamily(vendor),
            backport_status=BackportStatus(backport_status),
            advisory_reference=(
                "TEST" if backport_status == "confirmed_fixed" else None
            ),
        )

    response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://example.test/"),
        headers=headers,
        text="reference",
    )

    assessment = assess_response(
        "https://example.test/",
        response,
        vendor_evidence=evidence,
        policy=policy,
    )

    assessment_vendor = assessment.vendor_evidence
    cve_report = decide_cves(
        php_detected=assessment.php_detected,
        php_version=assessment.php_version,
        vendor_family=(
            assessment_vendor.vendor.value
            if assessment_vendor is not None
            else None
        ),
        backport_status=(
            assessment_vendor.backport_status.value
            if assessment_vendor is not None
            else None
        ),
        sapi_hypothesis=assessment.fingerprint.sapi.value,
        policy=policy,
    )

    findings = build_findings(
        target=assessment.target,
        assessment=assessment,
        cve_report=cve_report,
    )

    assert assessment.status.value == expected_status

    validate_cross_layer_consistency(
        assessment=assessment,
        cve_report=cve_report,
        findings=findings,
    )


def test_consistency_rejects_potential_exposure_when_edge_not_reached():
    from php_sentinel.models.edge import (
        ApplicationReachability,
        EdgeAssessment,
        EdgeProvider,
        EdgeResponseClass,
    )

    assessment, cve_report, findings = _components()

    edge = EdgeAssessment(
        edge_detected=True,
        waf_detected=True,
        provider=EdgeProvider.CLOUDFLARE,
        response_class=EdgeResponseClass.BOT_CHALLENGE,
        application_reachability=ApplicationReachability.NOT_REACHED,
        challenge_detected=True,
    )

    with pytest.raises(
        CrossLayerConsistencyError,
        match="Edge-gated application evidence",
    ):
        validate_cross_layer_consistency(
            assessment=assessment,
            cve_report=cve_report,
            findings=findings,
            edge_assessment=edge,
        )
