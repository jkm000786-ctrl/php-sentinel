from __future__ import annotations

from packaging.version import (
    InvalidVersion,
    Version,
)

from php_sentinel.intelligence.repository import (
    default_policy,
    fixed_version_for_branch,
)
from php_sentinel.models.cve_decision import (
    CVEDecision,
    CVEDecisionReport,
    CVEDecisionStatus,
    DecisionConfidence,
    ExposurePriority,
)
from php_sentinel.models.intelligence_policy import (
    CVEPolicy,
    IntelligencePolicy,
)

_POLICY = default_policy()


def _priority_from_name(
    value: str,
) -> ExposurePriority:
    try:
        return ExposurePriority(value)
    except ValueError:
        return ExposurePriority.UNKNOWN


def _priority(
    sapi: str | None,
    *,
    policy: IntelligencePolicy = _POLICY,
) -> ExposurePriority:
    normalized = (sapi or "").strip().lower()

    if normalized in policy.sapi_priority.critical:
        return ExposurePriority.CRITICAL

    if normalized in policy.sapi_priority.high:
        return ExposurePriority.HIGH

    if not normalized or normalized == "unknown":
        return _priority_from_name(policy.sapi_priority.unknown_priority)

    return _priority_from_name(policy.sapi_priority.other_priority)


def _remediation(
    definition: CVEPolicy,
    fixed_version: str | None,
    *,
    policy: IntelligencePolicy = _POLICY,
) -> list[str]:
    items: list[str] = []

    if fixed_version:
        items.append(policy.guidance.upgrade_template.format(fixed_version=fixed_version))
    else:
        items.append(policy.guidance.supported_branch_upgrade)

    items.extend(definition.temporary_mitigations)

    return items


def _decision_for_cve(
    definition: CVEPolicy,
    *,
    php_detected: bool,
    php_version: str | None,
    vendor_family: str | None,
    backport_status: str | None,
    sapi_hypothesis: str | None,
    policy: IntelligencePolicy = _POLICY,
) -> CVEDecision:
    priority = _priority(
        sapi_hypothesis,
        policy=policy,
    )

    if not php_detected:
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.NOT_APPLICABLE,
            confidence=DecisionConfidence.HIGH,
            exposure_priority=ExposurePriority.NONE,
            rationale=[("PHP was not detected in the supplied evidence.")],
        )

    if not php_version:
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.INCONCLUSIVE,
            confidence=DecisionConfidence.LOW,
            exposure_priority=priority,
            rationale=[("PHP was detected but no reliable PHP version was established.")],
            remediation=_remediation(
                definition,
                None,
                policy=policy,
            ),
        )

    try:
        version = Version(php_version)
    except InvalidVersion:
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.INCONCLUSIVE,
            confidence=DecisionConfidence.LOW,
            exposure_priority=priority,
            detected_version=php_version,
            rationale=[("The detected PHP version could not be parsed reliably.")],
            remediation=_remediation(
                definition,
                None,
                policy=policy,
            ),
        )

    branch = version.release[:2]

    if len(branch) != 2:
        fixed = None
    else:
        fixed = fixed_version_for_branch(
            (branch[0], branch[1]),
            policy=policy,
        )

    if fixed is None:
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=(CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE),
            confidence=DecisionConfidence.MEDIUM,
            exposure_priority=priority,
            detected_version=str(version),
            rationale=[
                (
                    "The detected PHP branch is outside "
                    "the explicitly modeled upstream "
                    "security-release matrix."
                ),
                (
                    "Do not infer CVE status solely from "
                    "the banner for an unmodeled or "
                    "vendor-maintained branch."
                ),
            ],
            remediation=_remediation(
                definition,
                None,
                policy=policy,
            ),
        )

    fixed_string = str(fixed)

    if version >= fixed:
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.PATCHED_UPSTREAM,
            confidence=DecisionConfidence.HIGH,
            exposure_priority=ExposurePriority.NONE,
            detected_version=str(version),
            fixed_version=fixed_string,
            rationale=[(f"PHP {version} meets or exceeds the upstream fixed threshold {fixed}.")],
            remediation=[policy.guidance.patched_upstream],
        )

    normalized_backport = (backport_status or "unknown").strip().lower()

    normalized_vendor = (vendor_family or "unknown").strip().lower()

    if normalized_backport == "confirmed_fixed":
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.PATCHED_VENDOR,
            confidence=DecisionConfidence.HIGH,
            exposure_priority=ExposurePriority.NONE,
            detected_version=str(version),
            fixed_version=fixed_string,
            rationale=[
                (
                    f"PHP {version} is below upstream "
                    f"threshold {fixed}, but authoritative "
                    "vendor evidence confirms the fix "
                    "was backported."
                )
            ],
            remediation=[policy.guidance.patched_vendor],
        )

    if normalized_backport == "probably_fixed":
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=(CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE),
            confidence=DecisionConfidence.MEDIUM,
            exposure_priority=priority,
            detected_version=str(version),
            fixed_version=fixed_string,
            rationale=[
                (
                    "Available evidence suggests a vendor "
                    "backport may exist, but it has not "
                    "been confirmed."
                )
            ],
            remediation=_remediation(
                definition,
                fixed_string,
                policy=policy,
            ),
        )

    if normalized_vendor == "upstream" or normalized_backport == "no_fix_evidence":
        rationale = [(f"PHP {version} is below the upstream fixed threshold {fixed}.")]

        if normalized_vendor == "upstream":
            rationale.append(
                "The runtime is identified as an "
                "upstream PHP build, so vendor "
                "backport ambiguity does not apply."
            )
        else:
            rationale.append(
                "No vendor fix evidence was supplied; "
                "absence of such evidence is not itself "
                "proof of exploitation."
            )

        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=(CVEDecisionStatus.POTENTIALLY_AFFECTED),
            confidence=(
                DecisionConfidence.HIGH
                if normalized_vendor == "upstream"
                else DecisionConfidence.MEDIUM
            ),
            exposure_priority=priority,
            detected_version=str(version),
            fixed_version=fixed_string,
            rationale=rationale,
            remediation=_remediation(
                definition,
                fixed_string,
                policy=policy,
            ),
        )

    return CVEDecision(
        cve_id=definition.cve_id,
        title=definition.title,
        status=(CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE),
        confidence=DecisionConfidence.MEDIUM,
        exposure_priority=priority,
        detected_version=str(version),
        fixed_version=fixed_string,
        rationale=[
            (f"PHP {version} is below the upstream fixed threshold {fixed}."),
            (
                "The package vendor/backport state is "
                "unresolved, so the banner alone cannot "
                "establish vulnerability."
            ),
        ],
        remediation=_remediation(
            definition,
            fixed_string,
            policy=policy,
        ),
    )


def decide_cves(
    *,
    php_detected: bool,
    php_version: str | None,
    vendor_family: str | None = None,
    backport_status: str | None = None,
    sapi_hypothesis: str | None = None,
    policy: IntelligencePolicy | None = None,
) -> CVEDecisionReport:
    selected = policy or _POLICY

    decisions = [
        _decision_for_cve(
            definition,
            php_detected=php_detected,
            php_version=php_version,
            vendor_family=vendor_family,
            backport_status=backport_status,
            sapi_hypothesis=sapi_hypothesis,
            policy=selected,
        )
        for definition in selected.cves
    ]

    return CVEDecisionReport(
        php_detected=php_detected,
        php_version=php_version,
        vendor_family=vendor_family,
        backport_status=backport_status,
        sapi_hypothesis=sapi_hypothesis,
        decisions=decisions,
        notes=list(selected.notes),
    )
