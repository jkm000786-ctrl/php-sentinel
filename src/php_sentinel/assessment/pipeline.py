from __future__ import annotations

import hashlib

from php_sentinel.assessment.exposure import assess_response
from php_sentinel.http.client import fetch
from php_sentinel.intelligence.cve_decision_engine import decide_cves
from php_sentinel.models.unified import (
    HTTPMetadata,
    UnifiedAssessmentReport,
)
from php_sentinel.models.validation import ValidationReport
from php_sentinel.models.vendor import (
    BackportStatus,
    VendorEvidence,
    VendorFamily,
)


def build_vendor_evidence(
    *,
    vendor: VendorFamily,
    package_name: str | None,
    package_version: str | None,
    backport_status: BackportStatus,
    advisory_reference: str | None,
) -> VendorEvidence | None:
    has_vendor_evidence = any(
        (
            vendor != VendorFamily.UNKNOWN,
            package_name,
            package_version,
            backport_status != BackportStatus.UNKNOWN,
            advisory_reference,
        )
    )

    if not has_vendor_evidence:
        return None

    return VendorEvidence(
        vendor=vendor,
        package_name=package_name,
        package_version=package_version,
        backport_status=backport_status,
        advisory_reference=advisory_reference,
        source="operator-supplied",
    )


def run_unified_assessment(
    target: str,
    *,
    timeout: float = 10.0,
    vendor: VendorFamily = VendorFamily.UNKNOWN,
    package_name: str | None = None,
    package_version: str | None = None,
    backport_status: BackportStatus = BackportStatus.UNKNOWN,
    advisory_reference: str | None = None,
    lab_validation: ValidationReport | None = None,
) -> UnifiedAssessmentReport:
    vendor_evidence = build_vendor_evidence(
        vendor=vendor,
        package_name=package_name,
        package_version=package_version,
        backport_status=backport_status,
        advisory_reference=advisory_reference,
    )

    response = fetch(
        target,
        timeout=timeout,
    )

    assessment = assess_response(
        target,
        response,
        vendor_evidence=vendor_evidence,
    )

    assessment_vendor = assessment.vendor_evidence

    cve_report = decide_cves(
        php_detected=assessment.php_detected,
        php_version=assessment.php_version,
        vendor_family=(assessment_vendor.vendor.value if assessment_vendor else None),
        backport_status=(assessment_vendor.backport_status.value if assessment_vendor else None),
        sapi_hypothesis=assessment.fingerprint.sapi.value,
    )

    body = response.content

    metadata = HTTPMetadata(
        requested_url=target,
        final_url=str(response.url),
        status_code=response.status_code,
        redirect_count=len(response.history),
        content_type=response.headers.get("content-type"),
        server=response.headers.get("server"),
        x_powered_by=response.headers.get("x-powered-by"),
        body_length=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
    )

    return UnifiedAssessmentReport(
        target=target,
        http=metadata,
        assessment=assessment,
        cve_decisions=cve_report,
        lab_validation=lab_validation,
        notes=[
            (
                "The unified pipeline reuses the canonical HTTP, PHP "
                "fingerprinting, SAPI, vendor/backport, and CVE engines."
            ),
            (
                "Response bodies are not persisted in unified evidence; "
                "only their length and SHA-256 digest are retained."
            ),
            ("CVE applicability is not equivalent to successful exploitation."),
        ],
    )
