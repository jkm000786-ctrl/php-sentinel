from unittest.mock import patch

import httpx

from php_sentinel.assessment.pipeline import (
    run_unified_assessment,
)
from php_sentinel.comparison.engine import (
    compare_reports,
)
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
        text=f"runtime={version}",
    )


@patch("php_sentinel.assessment.pipeline.fetch")
def test_candidate_to_patched_is_remediated(
    mock_fetch,
):
    mock_fetch.side_effect = [
        response("8.5.11"),
        response("8.5.12"),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.overall_state.value == "remediated"

    assert all(change.transition.value == "remediated" for change in result.cve_changes)


@patch("php_sentinel.assessment.pipeline.fetch")
def test_patched_to_candidate_is_regressed(
    mock_fetch,
):
    mock_fetch.side_effect = [
        response("8.5.12"),
        response("8.5.11"),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.overall_state.value == "regressed"


@patch("php_sentinel.assessment.pipeline.fetch")
def test_same_evidence_is_unchanged(
    mock_fetch,
):
    mock_fetch.side_effect = [
        response("8.5.12"),
        response("8.5.12"),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.overall_state.value == "unchanged"

    assert result.same_canonical_evidence is True
