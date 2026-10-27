from unittest.mock import patch

import httpx

from php_sentinel.assessment.pipeline import run_unified_assessment
from php_sentinel.models.vendor import VendorFamily


def response(version: str) -> httpx.Response:
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
        },
        text="reference",
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_candidate_generates_two_critical_potential_findings(
    mock_fetch,
):
    mock_fetch.return_value = response("8.5.11")

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    assert len(report.findings) == 2

    for finding in report.findings:
        assert finding.state.value == "potential_exposure"
        assert finding.severity.value == "critical"
        assert finding.confidence == "high"


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_patched_runtime_generates_informational_findings(
    mock_fetch,
):
    mock_fetch.return_value = response("8.5.12")

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    for finding in report.findings:
        assert finding.state.value == "patched"
        assert finding.severity.value == "informational"
