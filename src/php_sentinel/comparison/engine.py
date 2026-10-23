from __future__ import annotations

from php_sentinel.models.comparison import (
    ComparisonReport,
    ComparisonState,
    CVEChange,
)
from php_sentinel.models.unified import UnifiedAssessmentReport

RISK_RANK = {
    "not_applicable": 0,
    "patched": 0,
    "inconclusive": 1,
    "needs_evidence": 2,
    "potential_exposure": 3,
}


def _transition(
    before: str | None,
    after: str | None,
) -> ComparisonState:
    if before == after:
        return ComparisonState.UNCHANGED

    before_rank = RISK_RANK.get(
        before or "",
        1,
    )
    after_rank = RISK_RANK.get(
        after or "",
        1,
    )

    if after_rank < before_rank:
        return ComparisonState.REMEDIATED

    if after_rank > before_rank:
        return ComparisonState.REGRESSED

    return ComparisonState.EVIDENCE_CHANGED


def compare_reports(
    before: UnifiedAssessmentReport,
    after: UnifiedAssessmentReport,
) -> ComparisonReport:
    before_findings = {finding.cve_id: finding for finding in before.findings}

    after_findings = {finding.cve_id: finding for finding in after.findings}

    cve_ids = sorted(set(before_findings) | set(after_findings))

    cve_changes: list[CVEChange] = []

    for cve_id in cve_ids:
        before_finding = before_findings.get(cve_id)
        after_finding = after_findings.get(cve_id)

        before_state = before_finding.state.value if before_finding else None

        after_state = after_finding.state.value if after_finding else None

        cve_changes.append(
            CVEChange(
                cve_id=cve_id,
                before_state=before_state,
                after_state=after_state,
                before_severity=(before_finding.severity.value if before_finding else None),
                after_severity=(after_finding.severity.value if after_finding else None),
                transition=_transition(
                    before_state,
                    after_state,
                ),
            )
        )

    transitions = {change.transition for change in cve_changes}

    if ComparisonState.REGRESSED in transitions:
        overall = ComparisonState.REGRESSED
    elif (
        transitions
        and transitions
        <= {
            ComparisonState.REMEDIATED,
            ComparisonState.UNCHANGED,
        }
        and ComparisonState.REMEDIATED in transitions
    ):
        overall = ComparisonState.REMEDIATED
    elif transitions == {ComparisonState.UNCHANGED}:
        overall = ComparisonState.UNCHANGED
    else:
        overall = ComparisonState.EVIDENCE_CHANGED

    same_requested_target = before.http.requested_url == after.http.requested_url

    same_target_identity = (
        before.provenance.target_identity_sha256 == after.provenance.target_identity_sha256
    )

    same_policy_version = before.provenance.policy_version == after.provenance.policy_version

    same_canonical_evidence = (
        before.provenance.canonical_sha256 == after.provenance.canonical_sha256
    )

    changes: list[str] = []

    if before.assessment.php_version != after.assessment.php_version:
        changes.append(
            "PHP version changed: "
            f"{before.assessment.php_version or 'unknown'} "
            "-> "
            f"{after.assessment.php_version or 'unknown'}."
        )

    if before.assessment.status.value != after.assessment.status.value:
        changes.append(
            "Overall assessment changed: "
            f"{before.assessment.status.value} "
            "-> "
            f"{after.assessment.status.value}."
        )

    if before.assessment.fingerprint.sapi.value != after.assessment.fingerprint.sapi.value:
        changes.append(
            "SAPI hypothesis changed: "
            f"{before.assessment.fingerprint.sapi.value} "
            "-> "
            f"{after.assessment.fingerprint.sapi.value}."
        )

    if before.http.body_sha256 != after.http.body_sha256:
        changes.append("Response body SHA-256 changed.")

    if not same_target_identity:
        changes.append("Target identity SHA-256 changed.")

    if not same_policy_version:
        changes.append(
            "Policy version changed: "
            f"{before.provenance.policy_version} "
            "-> "
            f"{after.provenance.policy_version}."
        )

    if not same_requested_target:
        changes.append(
            f"Requested target changed: {before.http.requested_url} -> {after.http.requested_url}."
        )

    return ComparisonReport(
        before_report_id=before.provenance.report_id,
        after_report_id=after.provenance.report_id,
        before_target=before.target,
        after_target=after.target,
        overall_state=overall,
        same_requested_target=same_requested_target,
        same_target_identity=same_target_identity,
        same_policy_version=same_policy_version,
        same_canonical_evidence=same_canonical_evidence,
        php_version_before=before.assessment.php_version,
        php_version_after=after.assessment.php_version,
        assessment_before=before.assessment.status.value,
        assessment_after=after.assessment.status.value,
        changes=changes,
        cve_changes=cve_changes,
    )
