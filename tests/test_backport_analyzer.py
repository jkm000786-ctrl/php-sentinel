from php_sentinel.intelligence.backport_analyzer import analyze_backport
from php_sentinel.models.vendor import (
    BackportStatus,
    VendorEvidence,
    VendorFamily,
)


def test_confirmed_vendor_fix():
    evidence = VendorEvidence(
        vendor=VendorFamily.UBUNTU,
        package_name="php8.5",
        package_version="8.5.11-ubuntu-security",
        backport_status=BackportStatus.CONFIRMED_FIXED,
        advisory_reference="TEST-ADVISORY",
    )

    result = analyze_backport(evidence)

    assert result.fixed_by_vendor is True
    assert result.confidence == "high"


def test_probable_fix_is_not_promoted_to_fact():
    evidence = VendorEvidence(
        vendor=VendorFamily.DEBIAN,
        backport_status=BackportStatus.PROBABLY_FIXED,
    )

    result = analyze_backport(evidence)

    assert result.fixed_by_vendor is None


def test_no_vendor_evidence_is_unknown():
    result = analyze_backport(None)

    assert result.fixed_by_vendor is None
