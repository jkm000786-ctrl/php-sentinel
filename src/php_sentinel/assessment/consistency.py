from __future__ import annotations

from php_sentinel.models.assessment import Assessment, AssessmentStatus
from php_sentinel.models.cve_decision import (
    CVEDecision,
    CVEDecisionReport,
    CVEDecisionStatus,
    ExposurePriority,
)
from php_sentinel.models.edge import (
    ApplicationReachability,
    EdgeAssessment,
    EdgeResponseClass,
)
from php_sentinel.models.finding import Finding, FindingSeverity, FindingState


class CrossLayerConsistencyError(ValueError):
    """Raised when assessment, CVE, and finding layers contradict each other."""


_ASSESSMENT_TO_CVE_STATUS = {
    AssessmentStatus.NOT_PHP: CVEDecisionStatus.NOT_APPLICABLE,
    AssessmentStatus.PATCHED_UPSTREAM: CVEDecisionStatus.PATCHED_UPSTREAM,
    AssessmentStatus.PATCHED_VENDOR: CVEDecisionStatus.PATCHED_VENDOR,
    AssessmentStatus.POTENTIALLY_AFFECTED: CVEDecisionStatus.POTENTIALLY_AFFECTED,
    AssessmentStatus.NEEDS_VENDOR_EVIDENCE: CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE,
    AssessmentStatus.INCONCLUSIVE: CVEDecisionStatus.INCONCLUSIVE,
}

_CVE_TO_FINDING_STATE = {
    CVEDecisionStatus.PATCHED_UPSTREAM: FindingState.PATCHED,
    CVEDecisionStatus.PATCHED_VENDOR: FindingState.PATCHED,
    CVEDecisionStatus.POTENTIALLY_AFFECTED: FindingState.POTENTIAL_EXPOSURE,
    CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE: FindingState.NEEDS_EVIDENCE,
    CVEDecisionStatus.NOT_APPLICABLE: FindingState.NOT_APPLICABLE,
    CVEDecisionStatus.INCONCLUSIVE: FindingState.INCONCLUSIVE,
}


def _expected_severity(decision: CVEDecision) -> FindingSeverity:
    if decision.status in {
        CVEDecisionStatus.PATCHED_UPSTREAM,
        CVEDecisionStatus.PATCHED_VENDOR,
        CVEDecisionStatus.NOT_APPLICABLE,
    }:
        return FindingSeverity.INFORMATIONAL

    if decision.status == CVEDecisionStatus.POTENTIALLY_AFFECTED:
        if decision.exposure_priority == ExposurePriority.CRITICAL:
            return FindingSeverity.CRITICAL
        if decision.exposure_priority in {
            ExposurePriority.HIGH,
            ExposurePriority.ELEVATED,
        }:
            return FindingSeverity.HIGH
        return FindingSeverity.MEDIUM

    if decision.status == CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE:
        if decision.exposure_priority in {
            ExposurePriority.CRITICAL,
            ExposurePriority.HIGH,
        }:
            return FindingSeverity.HIGH
        return FindingSeverity.MEDIUM

    return FindingSeverity.LOW


def _fail(message: str) -> None:
    raise CrossLayerConsistencyError(
        f"Cross-layer assessment consistency violation: {message}"
    )


def validate_cross_layer_consistency(
    *,
    assessment: Assessment,
    cve_report: CVEDecisionReport,
    findings: list[Finding],
    edge_assessment: EdgeAssessment | None = None,
) -> None:
    """Fail closed when independently derived report layers contradict each other."""

    edge_application_suppressed = False

    if edge_assessment is not None:
        edge_application_suppressed = (
            edge_assessment.response_class != EdgeResponseClass.APPLICATION_RESPONSE
            or edge_assessment.application_reachability
            in {
                ApplicationReachability.UNKNOWN,
                ApplicationReachability.NOT_REACHED,
            }
        )

        if edge_application_suppressed:
            if assessment.status != AssessmentStatus.INCONCLUSIVE:
                _fail(
                    "Edge-gated application evidence must produce an "
                    "inconclusive top-level assessment."
                )

            if assessment.exposure_priority != ExposurePriority.UNKNOWN.value:
                _fail(
                    "Edge-gated application evidence must have unknown "
                    "exposure priority."
                )

            if any(
                item.status != CVEDecisionStatus.INCONCLUSIVE
                for item in cve_report.decisions
            ):
                _fail(
                    "Edge-gated application evidence must produce only "
                    "inconclusive CVE decisions."
                )

            if any(
                item.state != FindingState.INCONCLUSIVE
                for item in findings
            ):
                _fail(
                    "Edge-gated application evidence must produce only "
                    "inconclusive findings."
                )

    if cve_report.php_detected != assessment.php_detected:
        _fail("PHP detection state differs between assessment and CVE report.")

    if cve_report.php_version != assessment.php_version:
        _fail("PHP version differs between assessment and CVE report.")

    expected_sapi = assessment.fingerprint.sapi.value
    if cve_report.sapi_hypothesis != expected_sapi:
        _fail("SAPI hypothesis differs between assessment and CVE report.")

    expected_vendor = (
        assessment.vendor_evidence.vendor.value
        if assessment.vendor_evidence is not None
        else None
    )
    expected_backport = (
        assessment.vendor_evidence.backport_status.value
        if assessment.vendor_evidence is not None
        else None
    )

    if cve_report.vendor_family != expected_vendor:
        _fail("Vendor family differs between assessment and CVE report.")

    if cve_report.backport_status != expected_backport:
        _fail("Backport state differs between assessment and CVE report.")

    decisions = cve_report.decisions
    if not decisions:
        _fail("CVE decision report must contain at least one decision.")

    decision_ids = [item.cve_id for item in decisions]
    if len(decision_ids) != len(set(decision_ids)):
        _fail("CVE decision identifiers must be unique.")

    expected_status = _ASSESSMENT_TO_CVE_STATUS[assessment.status]
    unexpected_statuses = {
        item.status for item in decisions if item.status != expected_status
    }
    if unexpected_statuses:
        rendered = ", ".join(sorted(item.value for item in unexpected_statuses))
        _fail(
            "Top-level assessment status does not match CVE decision status set: "
            f"{rendered}."
        )

    try:
        assessment_priority = ExposurePriority(assessment.exposure_priority)
    except ValueError as exc:
        raise CrossLayerConsistencyError(
            "Cross-layer assessment consistency violation: "
            f"non-canonical assessment exposure priority "
            f"{assessment.exposure_priority!r}."
        ) from exc

    unexpected_priorities = {
        item.exposure_priority
        for item in decisions
        if item.exposure_priority != assessment_priority
    }
    if unexpected_priorities:
        rendered = ", ".join(sorted(item.value for item in unexpected_priorities))
        _fail(
            "Top-level assessment exposure priority does not match CVE decisions: "
            f"{rendered}."
        )

    decision_id_set = set(decision_ids)
    if assessment.status in {
        AssessmentStatus.NOT_PHP,
        AssessmentStatus.PATCHED_UPSTREAM,
        AssessmentStatus.PATCHED_VENDOR,
    } or edge_application_suppressed:
        expected_applicable_cves: set[str] = set()
    else:
        expected_applicable_cves = decision_id_set

    if set(assessment.applicable_cves) != expected_applicable_cves:
        _fail("Top-level applicable CVE set does not match CVE decision identifiers.")

    finding_ids = [item.cve_id for item in findings]
    if len(finding_ids) != len(set(finding_ids)):
        _fail("Finding CVE identifiers must be unique.")

    if set(finding_ids) != decision_id_set:
        _fail("Finding CVE set does not match CVE decision identifiers.")

    findings_by_cve = {item.cve_id: item for item in findings}

    for decision in decisions:
        finding = findings_by_cve[decision.cve_id]

        if finding.finding_id != f"PHP-SENTINEL-{decision.cve_id}":
            _fail(f"Finding identity mismatch for {decision.cve_id}.")

        if finding.title != decision.title:
            _fail(f"Finding title mismatch for {decision.cve_id}.")

        expected_finding_state = _CVE_TO_FINDING_STATE[decision.status]
        if finding.state != expected_finding_state:
            _fail(f"Finding state mismatch for {decision.cve_id}.")

        if finding.severity != _expected_severity(decision):
            _fail(f"Finding severity mismatch for {decision.cve_id}.")

        if finding.confidence != decision.confidence.value:
            _fail(f"Finding confidence mismatch for {decision.cve_id}.")

        if finding.target != assessment.target:
            _fail(f"Finding target mismatch for {decision.cve_id}.")

        if finding.detected_version != decision.detected_version:
            _fail(f"Finding detected version mismatch for {decision.cve_id}.")

        if finding.fixed_version != decision.fixed_version:
            _fail(f"Finding fixed version mismatch for {decision.cve_id}.")

        if finding.sapi_hypothesis != expected_sapi:
            _fail(f"Finding SAPI hypothesis mismatch for {decision.cve_id}.")

        if finding.rationale != decision.rationale:
            _fail(f"Finding rationale mismatch for {decision.cve_id}.")

        if finding.remediation != decision.remediation:
            _fail(f"Finding remediation mismatch for {decision.cve_id}.")
