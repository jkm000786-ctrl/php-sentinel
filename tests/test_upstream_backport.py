from php_sentinel.intelligence.backport_analyzer import analyze_backport
from php_sentinel.models.vendor import (
    BackportStatus,
    VendorEvidence,
    VendorFamily,
)


def test_upstream_build_has_no_vendor_backport_ambiguity():
    evidence = VendorEvidence(
        vendor=VendorFamily.UPSTREAM,
        backport_status=BackportStatus.UNKNOWN,
        source="operator-supplied",
    )

    decision = analyze_backport(evidence)

    assert decision.fixed_by_vendor is False
    assert decision.confidence == "high"
    assert "does not apply" in " ".join(decision.rationale).lower()
