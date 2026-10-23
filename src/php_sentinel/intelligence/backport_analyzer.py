from __future__ import annotations

from dataclasses import dataclass

from php_sentinel.models.vendor import (
    BackportStatus,
    VendorEvidence,
    VendorFamily,
)


@dataclass(frozen=True)
class BackportDecision:
    fixed_by_vendor: bool | None
    confidence: str
    rationale: tuple[str, ...]


def analyze_backport(
    evidence: VendorEvidence | None,
) -> BackportDecision:
    if evidence is None:
        return BackportDecision(
            fixed_by_vendor=None,
            confidence="none",
            rationale=("No vendor security evidence was supplied.",),
        )

    if evidence.vendor == VendorFamily.UPSTREAM:
        return BackportDecision(
            fixed_by_vendor=False,
            confidence="high",
            rationale=(
                (
                    "The runtime is identified as an upstream PHP build; "
                    "vendor backport ambiguity does not apply."
                ),
            ),
        )

    if evidence.backport_status == BackportStatus.CONFIRMED_FIXED:
        reasons = ["Vendor evidence explicitly confirms the security fix."]

        if evidence.advisory_reference:
            reasons.append(f"Vendor advisory/reference: {evidence.advisory_reference}")

        return BackportDecision(
            fixed_by_vendor=True,
            confidence="high",
            rationale=tuple(reasons),
        )

    if evidence.backport_status == BackportStatus.PROBABLY_FIXED:
        return BackportDecision(
            fixed_by_vendor=None,
            confidence="medium",
            rationale=("Evidence suggests a vendor backport, but confirmation is incomplete.",),
        )

    if evidence.backport_status == BackportStatus.NO_FIX_EVIDENCE:
        return BackportDecision(
            fixed_by_vendor=False,
            confidence="medium",
            rationale=(
                "No vendor fix evidence was identified for the supplied package evidence.",
                "Absence of evidence is not equivalent to proof that no fix exists.",
            ),
        )

    return BackportDecision(
        fixed_by_vendor=None,
        confidence="low",
        rationale=("Vendor backport status is unknown.",),
    )
