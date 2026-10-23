import httpx

from php_sentinel.assessment.exposure import assess_response
from php_sentinel.models.vendor import (
    VendorEvidence,
    VendorFamily,
)


def test_upstream_candidate_does_not_request_os_vendor_advisory():
    request = httpx.Request(
        "GET",
        "http://127.0.0.1/",
    )

    response = httpx.Response(
        200,
        request=request,
        headers={
            "Server": "Apache",
            "X-Powered-By": "PHP/8.5.11",
        },
        text="candidate",
    )

    result = assess_response(
        "http://127.0.0.1/",
        response,
        vendor_evidence=VendorEvidence(
            vendor=VendorFamily.UPSTREAM,
            source="operator-supplied",
        ),
    )

    remediation = " ".join(result.remediation).lower()

    assert "operating-system vendor" not in remediation
    assert "upgrade" in remediation
