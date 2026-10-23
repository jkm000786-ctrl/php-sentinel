import httpx

from php_sentinel.assessment.exposure import assess_response
from php_sentinel.models.assessment import AssessmentStatus
from php_sentinel.models.vendor import (
    BackportStatus,
    VendorEvidence,
    VendorFamily,
)


def make_response(version: str) -> httpx.Response:
    request = httpx.Request(
        "GET",
        "https://example.test/",
    )

    return httpx.Response(
        200,
        headers={
            "Server": "Apache/2.4",
            "X-Powered-By": f"PHP/{version}",
        },
        text="ok",
        request=request,
    )


def test_old_upstream_banner_with_confirmed_backport_is_vendor_patched():
    evidence = VendorEvidence(
        vendor=VendorFamily.UBUNTU,
        package_name="php8.5",
        package_version="8.5.11-ubuntu-test",
        backport_status=BackportStatus.CONFIRMED_FIXED,
        advisory_reference="TEST-SECURITY-ADVISORY",
    )

    result = assess_response(
        "https://example.test/",
        make_response("8.5.11"),
        vendor_evidence=evidence,
    )

    assert result.status == AssessmentStatus.PATCHED_VENDOR
    assert result.applicable_cves == []


def test_old_upstream_banner_without_vendor_evidence_needs_evidence():
    result = assess_response(
        "https://example.test/",
        make_response("8.5.11"),
    )

    assert result.status == AssessmentStatus.NEEDS_VENDOR_EVIDENCE


def test_no_fix_evidence_is_potentially_affected_not_confirmed_vulnerable():
    evidence = VendorEvidence(
        vendor=VendorFamily.CUSTOM,
        package_name="php",
        package_version="8.5.11",
        backport_status=BackportStatus.NO_FIX_EVIDENCE,
    )

    result = assess_response(
        "https://example.test/",
        make_response("8.5.11"),
        vendor_evidence=evidence,
    )

    assert result.status == AssessmentStatus.POTENTIALLY_AFFECTED
