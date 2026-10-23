from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from php_sentinel.models.cve_decision import (
    CVEDecision,
    CVEDecisionReport,
    CVEDecisionStatus,
    DecisionConfidence,
    ExposurePriority,
)


@dataclass(frozen=True)
class CVEDefinition:
    cve_id: str
    title: str


CVE_DEFINITIONS = (
    CVEDefinition(
        cve_id="CVE-2026-109618",
        title="RCE via out-of-memory state corruption",
    ),
    CVEDefinition(
        cve_id="CVE-2026-109619",
        title="RCE via stale global request state",
    ),
)


FIXED_VERSIONS: dict[tuple[int, int], Version] = {
    (8, 5): Version("8.5.12"),
    (8, 4): Version("8.4.27"),
    (8, 3): Version("8.3.36"),
    (8, 2): Version("8.2.35"),
}


WEB_SAPIS = {
    "mod_php",
    "fpm_fastcgi",
    "cgi",
    "litespeed",
    "frankenphp",
}


def _priority(sapi: str | None) -> ExposurePriority:
    normalized = (sapi or "").strip().lower()

    if normalized == "mod_php":
        return ExposurePriority.CRITICAL

    if normalized in WEB_SAPIS:
        return ExposurePriority.HIGH

    if not normalized or normalized == "unknown":
        return ExposurePriority.ELEVATED

    return ExposurePriority.UNKNOWN


def _remediation(
    cve_id: str,
    fixed_version: str | None,
) -> list[str]:
    items: list[str] = []

    if fixed_version:
        items.append(f"Upgrade to PHP {fixed_version} or a later supported release.")
    else:
        items.append(
            "Move to a currently supported PHP branch and apply the latest security release."
        )

    if cve_id == "CVE-2026-109619":
        items.append(
            "Until PHP's next regular bugfix release, consider setting "
            "session.upload_progress.enabled=0 in accordance with the "
            "23 October 2026 PHP informational advisory."
        )

    return items


def _decision_for_cve(
    definition: CVEDefinition,
    *,
    php_detected: bool,
    php_version: str | None,
    vendor_family: str | None,
    backport_status: str | None,
    sapi_hypothesis: str | None,
) -> CVEDecision:
    priority = _priority(sapi_hypothesis)

    if not php_detected:
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.NOT_APPLICABLE,
            confidence=DecisionConfidence.HIGH,
            exposure_priority=ExposurePriority.NONE,
            rationale=["PHP was not detected in the supplied evidence."],
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
                definition.cve_id,
                None,
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
            rationale=["The detected PHP version could not be parsed reliably."],
            remediation=_remediation(
                definition.cve_id,
                None,
            ),
        )

    branch = version.release[:2]
    fixed = FIXED_VERSIONS.get(branch)

    if fixed is None:
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE,
            confidence=DecisionConfidence.MEDIUM,
            exposure_priority=priority,
            detected_version=str(version),
            rationale=[
                (
                    "The detected PHP branch is outside the explicitly "
                    "modeled upstream 8.2-8.5 security-release matrix."
                ),
                (
                    "Do not infer CVE status solely from the banner for "
                    "an unmodeled or vendor-maintained branch."
                ),
            ],
            remediation=_remediation(
                definition.cve_id,
                None,
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
            remediation=[("Maintain current security patching and monitor future PHP advisories.")],
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
                    f"PHP {version} is below upstream threshold {fixed}, "
                    "but authoritative vendor evidence confirms the fix "
                    "was backported."
                )
            ],
            remediation=[
                (
                    "Maintain the vendor-supported package and preserve the "
                    "advisory/package evidence establishing the backport."
                )
            ],
        )

    if normalized_backport == "probably_fixed":
        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE,
            confidence=DecisionConfidence.MEDIUM,
            exposure_priority=priority,
            detected_version=str(version),
            fixed_version=fixed_string,
            rationale=[
                (
                    "Available evidence suggests a vendor backport may "
                    "exist, but it has not been confirmed."
                )
            ],
            remediation=_remediation(
                definition.cve_id,
                fixed_string,
            ),
        )

    if normalized_vendor == "upstream" or normalized_backport == "no_fix_evidence":
        rationale = [(f"PHP {version} is below the upstream fixed threshold {fixed}.")]

        if normalized_vendor == "upstream":
            rationale.append(
                "The runtime is identified as an upstream PHP build, "
                "so vendor backport ambiguity does not apply."
            )
        else:
            rationale.append(
                "No vendor fix evidence was supplied; absence of such "
                "evidence is not itself proof of exploitation."
            )

        return CVEDecision(
            cve_id=definition.cve_id,
            title=definition.title,
            status=CVEDecisionStatus.POTENTIALLY_AFFECTED,
            confidence=DecisionConfidence.HIGH
            if normalized_vendor == "upstream"
            else DecisionConfidence.MEDIUM,
            exposure_priority=priority,
            detected_version=str(version),
            fixed_version=fixed_string,
            rationale=rationale,
            remediation=_remediation(
                definition.cve_id,
                fixed_string,
            ),
        )

    return CVEDecision(
        cve_id=definition.cve_id,
        title=definition.title,
        status=CVEDecisionStatus.NEEDS_VENDOR_EVIDENCE,
        confidence=DecisionConfidence.MEDIUM,
        exposure_priority=priority,
        detected_version=str(version),
        fixed_version=fixed_string,
        rationale=[
            (f"PHP {version} is below the upstream fixed threshold {fixed}."),
            (
                "The package vendor/backport state is unresolved, so "
                "the banner alone cannot establish vulnerability."
            ),
        ],
        remediation=_remediation(
            definition.cve_id,
            fixed_string,
        ),
    )


def decide_cves(
    *,
    php_detected: bool,
    php_version: str | None,
    vendor_family: str | None = None,
    backport_status: str | None = None,
    sapi_hypothesis: str | None = None,
) -> CVEDecisionReport:
    decisions = [
        _decision_for_cve(
            definition,
            php_detected=php_detected,
            php_version=php_version,
            vendor_family=vendor_family,
            backport_status=backport_status,
            sapi_hypothesis=sapi_hypothesis,
        )
        for definition in CVE_DEFINITIONS
    ]

    return CVEDecisionReport(
        php_detected=php_detected,
        php_version=php_version,
        vendor_family=vendor_family,
        backport_status=backport_status,
        sapi_hypothesis=sapi_hypothesis,
        decisions=decisions,
        notes=[
            (
                "CVE decisions are evidence-based applicability "
                "assessments, not exploit confirmations."
            ),
            (
                "A potentially_affected result means the modeled "
                "preconditions are present; it does not prove successful "
                "exploitation."
            ),
            (
                "Vendor/LTS packages may contain security backports "
                "without changing the upstream-looking PHP version."
            ),
        ],
    )
