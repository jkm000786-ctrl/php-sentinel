from __future__ import annotations

from php_sentinel.models.assessment import AssessmentStatus


def remediation_for(status: AssessmentStatus) -> tuple[str, ...]:
    if status == AssessmentStatus.PATCHED_UPSTREAM:
        return (
            "Maintain the currently patched upstream PHP release.",
            "Continue normal patch-management monitoring.",
        )

    if status == AssessmentStatus.PATCHED_VENDOR:
        return (
            "Retain the vendor package containing the confirmed security backport.",
            "Preserve vendor advisory/package evidence for auditability.",
        )

    if status == AssessmentStatus.POTENTIALLY_AFFECTED:
        return (
            "Verify the installed package against the operating-system vendor security advisory.",
            "Upgrade to a confirmed fixed upstream or vendor-patched package.",
            "Do not rely on banner suppression as mitigation.",
        )

    if status == AssessmentStatus.NEEDS_VENDOR_EVIDENCE:
        return (
            "Collect package-manager version and vendor security advisory evidence.",
            "Do not classify the service as vulnerable solely from the HTTP version banner.",
        )

    if status == AssessmentStatus.NOT_PHP:
        return ("No PHP-specific remediation established from current evidence.",)

    return ("Collect additional runtime, package, and deployment evidence.",)
