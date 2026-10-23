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


@patch("php_sentinel.assessment.pipeline.fetch")
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


@patch("php_sentinel.assessment.pipeline.fetch")
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


@patch("php_sentinel.assessment.pipeline.fetch")
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


@patch("php_sentinel.assessment.pipeline.fetch")
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
