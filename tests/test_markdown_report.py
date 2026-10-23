from unittest.mock import patch

import httpx

from php_sentinel.assessment.pipeline import run_unified_assessment
from php_sentinel.models.vendor import VendorFamily
from php_sentinel.reporting.markdown import render_markdown_report


@patch("php_sentinel.assessment.pipeline.fetch")
def test_markdown_contains_findings_and_boundary(mock_fetch):
    request = httpx.Request(
        "GET",
        "http://127.0.0.1/",
    )

    mock_fetch.return_value = httpx.Response(
        200,
        request=request,
        headers={
            "Server": "Apache",
            "X-Powered-By": "PHP/8.5.11",
        },
        text="candidate",
    )

    report = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    markdown = render_markdown_report(report)

    assert "CVE-2026-109618" in markdown
    assert "CVE-2026-109619" in markdown
    assert "potential_exposure" in markdown
    assert "does **not** mean" in markdown
