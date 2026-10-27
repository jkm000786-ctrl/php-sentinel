from unittest.mock import patch

import httpx

from php_sentinel.assessment.pipeline import run_unified_assessment
from php_sentinel.models.vendor import VendorFamily


def response(
    version: str,
    body: str = "reference body",
) -> httpx.Response:
    request = httpx.Request(
        "GET",
        "http://127.0.0.1/",
    )

    return httpx.Response(
        200,
        request=request,
        headers={
            "Server": "Apache/2.4.69 (Debian)",
            "X-Powered-By": f"PHP/{version}",
            "Content-Type": "text/plain",
        },
        text=body,
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_unified_candidate_pipeline(mock_fetch):
    mock_fetch.return_value = response(
        "8.5.11",
        "candidate",
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    assert report.assessment.php_detected is True
    assert report.assessment.php_version == "8.5.11"
    assert report.assessment.status.value == "potentially_affected"

    statuses = {decision.status.value for decision in report.cve_decisions.decisions}

    assert statuses == {"potentially_affected"}
    assert report.http.body_length == len(b"candidate")
    assert len(report.http.body_sha256) == 64


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_unified_patched_pipeline(mock_fetch):
    mock_fetch.return_value = response(
        "8.5.12",
        "patched",
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    assert report.assessment.status.value == "patched_upstream"

    statuses = {decision.status.value for decision in report.cve_decisions.decisions}

    assert statuses == {"patched_upstream"}


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_unified_report_does_not_store_body(mock_fetch):
    secret_marker = "do-not-store-this-body"

    mock_fetch.return_value = response(
        "8.5.12",
        secret_marker,
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    serialized = report.model_dump_json()

    assert secret_marker not in serialized
    assert report.http.body_length == len(secret_marker.encode())


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_upstream_candidate_has_no_backport_contradiction(mock_fetch):
    mock_fetch.return_value = response(
        "8.5.11",
        "candidate",
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    rationale = " ".join(report.assessment.rationale).lower()

    assert "vendor backport ambiguity" in rationale
    assert "vendor may have backported" not in rationale


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_unified_report_contains_provenance(mock_fetch):
    mock_fetch.return_value = response(
        "8.5.11",
        "candidate",
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    assert report.provenance.report_id
    assert report.provenance.tool_name == "PHP Sentinel"
    assert len(report.provenance.canonical_sha256) == 64
    assert len(report.provenance.target_identity_sha256) == 64


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_unified_report_binds_intelligence_policy(
    mock_fetch,
):
    from php_sentinel.intelligence.repository import (
        default_policy,
        policy_sha256,
    )

    policy = default_policy()

    mock_fetch.return_value = httpx.Response(
        200,
        request=httpx.Request(
            "GET",
            "http://127.0.0.1/",
        ),
        headers={
            "Server": "Apache/2.4.69 (Debian)",
            "X-Powered-By": "PHP/8.5.12",
        },
        text="runtime=8.5.12",
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
        intelligence_policy=policy,
    )

    assert report.provenance.intelligence_policy_id == policy.policy_id

    assert report.provenance.intelligence_sha256 == policy_sha256(policy)


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_unified_pipeline_uses_one_policy_across_decision_layers(mock_fetch):
    from php_sentinel.intelligence.repository import default_policy

    policy = default_policy().model_copy(deep=True)
    policy.fixed_versions["8.5"] = "8.5.13"

    mock_fetch.return_value = response("8.5.12", "policy divergence regression")

    report = run_unified_assessment(
        "http://127.0.0.1/",
        intelligence_policy=policy,
    )

    assert report.assessment.status.value == "needs_vendor_evidence"
    assert report.assessment.exposure_priority == "critical"
    assert {item.status.value for item in report.cve_decisions.decisions} == {
        "needs_vendor_evidence"
    }
    assert {item.state.value for item in report.findings} == {"needs_evidence"}
    assert set(report.assessment.applicable_cves) == {
        item.cve_id for item in report.cve_decisions.decisions
    }


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_edge_challenge_suppresses_application_assessment(mock_fetch):
    mock_fetch.return_value = httpx.Response(
        403,
        request=httpx.Request("GET", "https://example.test/"),
        headers={
            "Server": "cloudflare",
            "CF-Ray": "opaque-trace",
            "CF-Mitigated": "challenge",
            "X-Powered-By": "PHP/8.5.11",
        },
        text="<title>Just a moment...</title>",
    )

    report = run_unified_assessment(
        "https://example.test/",
        vendor=VendorFamily.UPSTREAM,
    )

    assert report.edge.response_class.value == "bot_challenge"
    assert report.edge.application_reachability.value == "not_reached"
    assert report.assessment.status.value == "inconclusive"
    assert report.assessment.php_detected is False
    assert report.assessment.php_version is None
    assert report.assessment.exposure_priority == "unknown"
    assert report.assessment.applicable_cves == []
    assert {
        item.status.value
        for item in report.cve_decisions.decisions
    } == {"inconclusive"}
    assert {
        item.state.value
        for item in report.findings
    } == {"inconclusive"}
    assert report.provenance.edge_provider == "cloudflare"
    assert report.provenance.edge_response_class == "bot_challenge"
    assert report.provenance.application_reachability == "not_reached"


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_edge_only_response_cannot_create_php_exposure(mock_fetch):
    mock_fetch.return_value = httpx.Response(
        403,
        request=httpx.Request("GET", "https://example.test/"),
        headers={
            "X-Amz-Cf-Id": "opaque-id",
            "X-Amz-Cf-Pop": "KHI50-P1",
            "Via": "1.1 example.cloudfront.net (CloudFront)",
        },
        text="PHP Version 8.5.11",
    )

    report = run_unified_assessment("https://example.test/")

    assert report.edge.provider.value == "aws_cloudfront"
    assert report.edge.response_class.value == "edge_response"
    assert report.edge.application_reachability.value == "unknown"
    assert report.assessment.status.value == "inconclusive"
    assert report.assessment.php_detected is False
    assert report.assessment.php_confidence == 0.0
    assert all(
        item.state.value == "inconclusive"
        for item in report.findings
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_edge_with_independent_php_evidence_keeps_normal_pipeline(mock_fetch):
    mock_fetch.return_value = httpx.Response(
        200,
        request=httpx.Request("GET", "https://example.test/"),
        headers={
            "Server": "cloudflare",
            "CF-Ray": "opaque-id",
            "X-Powered-By": "PHP/8.5.11",
        },
        text="application",
    )

    report = run_unified_assessment(
        "https://example.test/",
        vendor=VendorFamily.UPSTREAM,
    )

    assert report.edge.response_class.value == "application_response"
    assert report.edge.application_reachability.value == "probable"
    assert report.assessment.php_detected is True
    assert report.assessment.status.value == "potentially_affected"
    assert {
        item.state.value
        for item in report.findings
    } == {"potential_exposure"}


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_unified_report_contains_transport_evidence(mock_fetch):
    mock_fetch.return_value = response(
        "8.5.12",
        "transport-evidence",
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    assert report.transport is not None
    assert report.transport.execution.attempts == 1
    assert report.transport.execution.requests_sent == 1
    assert report.transport.execution.retries == 0
    assert report.provenance.transport_attempts == 1
    assert report.provenance.transport_requests_sent == 1
    assert report.provenance.transport_retries == 0
    assert report.provenance.transport_stop_reason == "completed"


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_transport_execution_changes_canonical_not_target_identity(
    mock_fetch,
):
    from php_sentinel.models.transport import (
        TransportEvidence,
        TransportExecution,
    )

    first = response("8.5.12", "stable-identity")
    second = response("8.5.12", "stable-identity")

    first_transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
        )
    )

    second_transport = TransportEvidence(
        execution=TransportExecution(
            attempts=2,
            requests_sent=2,
            retries=1,
        )
    )

    mock_fetch.side_effect = [
        (first, first_transport),
        (second, second_transport),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    assert (
        before.provenance.canonical_sha256
        != after.provenance.canonical_sha256
    )

    assert (
        before.provenance.target_identity_sha256
        == after.provenance.target_identity_sha256
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_legacy_unified_report_without_transport_still_loads(
    mock_fetch,
):
    from php_sentinel.models.unified import UnifiedAssessmentReport

    mock_fetch.return_value = response(
        "8.5.12",
        "legacy-compatible",
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    payload = report.model_dump(mode="json")
    payload.pop("transport")

    legacy = UnifiedAssessmentReport.model_validate(payload)

    assert legacy.transport is None
    assert (
        legacy.provenance.target_identity_sha256
        == report.provenance.target_identity_sha256
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_transport_stop_suppresses_application_assessment(mock_fetch):
    from php_sentinel.models.transport import (
        TransportEvidence,
        TransportExecution,
        TransportStopReason,
    )

    blocked_response = httpx.Response(
        302,
        request=httpx.Request(
            "GET",
            "https://example.test/start",
        ),
        headers={
            "Location": "https://outside.test/",
            "Server": "Apache/2.4",
            "X-Powered-By": "PHP/8.5.11",
        },
        text="redirect",
    )

    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            redirect_target_denied=True,
            stop_reason=TransportStopReason.REDIRECT_TARGET_DENIED,
        )
    )

    mock_fetch.return_value = (
        blocked_response,
        transport,
    )

    report = run_unified_assessment(
        "https://example.test/start",
        vendor=VendorFamily.UPSTREAM,
    )

    assert (
        report.transport.execution.stop_reason.value
        == "redirect_target_denied"
    )
    assert report.assessment.status.value == "inconclusive"
    assert report.assessment.php_detected is False
    assert report.assessment.php_version is None
    assert report.assessment.php_confidence == 0.0
    assert report.assessment.exposure_priority == "unknown"
    assert report.assessment.applicable_cves == []

    assert {
        item.status.value
        for item in report.cve_decisions.decisions
    } == {"inconclusive"}

    assert {
        item.state.value
        for item in report.findings
    } == {"inconclusive"}
