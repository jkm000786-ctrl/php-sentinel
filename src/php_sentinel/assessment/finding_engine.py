from __future__ import annotations

from php_sentinel.models.assessment import Assessment
from php_sentinel.models.cve_decision import (
    CVEDecision,
    CVEDecisionReport,
    CVEDecisionStatus,
)
from php_sentinel.models.finding import (
    Finding,
    FindingSeverity,
    FindingState,
)


def _state(decision: CVEDecision) -> FindingState:
    mapping = {
        CVEDecisionStatus.PATCHED_UPSTREAM: FindingState.PATCHED,
        CVEDecisionStatus.PATCHED_VENDOR: FindingState.PATCHED,
        CVEDecisionStatus.POTENTIALLY_AFFECTED: (FindingState.POTENTIAL_EXPOSURE),
        CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE: (FindingState.NEEDS_EVIDENCE),
        CVEDecisionStatus.NOT_APPLICABLE: (FindingState.NOT_APPLICABLE),
        CVEDecisionStatus.INCONCLUSIVE: FindingState.INCONCLUSIVE,
    }

    return mapping[decision.status]


def _severity(decision: CVEDecision) -> FindingSeverity:
    if decision.status in {
        CVEDecisionStatus.PATCHED_UPSTREAM,
        CVEDecisionStatus.PATCHED_VENDOR,
        CVEDecisionStatus.NOT_APPLICABLE,
    }:
        return FindingSeverity.INFORMATIONAL

    if decision.status == CVEDecisionStatus.POTENTIALLY_AFFECTED:
        if decision.exposure_priority.value == "critical":
            return FindingSeverity.CRITICAL

        if decision.exposure_priority.value in {
            "high",
            "elevated",
        }:
            return FindingSeverity.HIGH

        return FindingSeverity.MEDIUM

    if decision.status == CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE:
        if decision.exposure_priority.value in {
            "critical",
            "high",
        }:
            return FindingSeverity.HIGH

        return FindingSeverity.MEDIUM

    return FindingSeverity.LOW


def build_findings(
    *,
    target: str,
    assessment: Assessment,
    cve_report: CVEDecisionReport,
) -> list[Finding]:
    findings: list[Finding] = []

    for decision in cve_report.decisions:
        evidence = [
            f"Target: {target}",
            (f"PHP detected: {assessment.php_detected}"),
            (f"PHP version: {assessment.php_version or 'unknown'}"),
            (f"Server: {assessment.server or 'unknown'}"),
            (
                "SAPI hypothesis: "
                f"{assessment.fingerprint.sapi.value} "
                f"({assessment.fingerprint.sapi_confidence:.0%})"
            ),
            (f"Overall assessment: {assessment.status.value}"),
        ]

        if assessment.vendor_evidence:
            evidence.extend(
                [
                    (f"Vendor: {assessment.vendor_evidence.vendor.value}"),
                    (f"Backport status: {assessment.vendor_evidence.backport_status.value}"),
                ]
            )

            if assessment.vendor_evidence.package_version:
                evidence.append(f"Package version: {assessment.vendor_evidence.package_version}")

            if assessment.vendor_evidence.advisory_reference:
                evidence.append(f"Vendor advisory: {assessment.vendor_evidence.advisory_reference}")

        findings.append(
            Finding(
                finding_id=(f"PHP-SENTINEL-{decision.cve_id}"),
                cve_id=decision.cve_id,
                title=decision.title,
                state=_state(decision),
                severity=_severity(decision),
                confidence=decision.confidence.value,
                target=target,
                detected_version=decision.detected_version,
                fixed_version=decision.fixed_version,
                sapi_hypothesis=assessment.fingerprint.sapi.value,
                evidence=evidence,
                rationale=list(decision.rationale),
                remediation=list(decision.remediation),
            )
        )

    return findings
