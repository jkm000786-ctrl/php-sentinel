from __future__ import annotations

import hashlib

from php_sentinel.assessment.consistency import validate_cross_layer_consistency
from php_sentinel.assessment.exposure import assess_response
from php_sentinel.assessment.finding_engine import build_findings
from php_sentinel.evidence.provenance import build_provenance
from php_sentinel.http.client import fetch
from php_sentinel.intelligence.activation import (
    VerifiedIntelligenceSelection,
)
from php_sentinel.intelligence.cve_decision_engine import decide_cves
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_identity,
)
from php_sentinel.models.intelligence_lifecycle import IntelligenceLifecycleDecision
from php_sentinel.models.intelligence_policy import IntelligencePolicy
from php_sentinel.models.intelligence_trust import IntelligenceTrustDecision
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
    intelligence_selection: VerifiedIntelligenceSelection | None = None,
    intelligence_policy: IntelligencePolicy | None = None,
    intelligence_trust: IntelligenceTrustDecision | None = None,
    intelligence_lifecycle: IntelligenceLifecycleDecision | None = None,
) -> UnifiedAssessmentReport:
    if intelligence_selection is not None:
        if any(
            item is not None
            for item in (
                intelligence_policy,
                intelligence_trust,
                intelligence_lifecycle,
            )
        ):
            raise ValueError(
                "Verified intelligence selection "
                "cannot be combined with legacy "
                "intelligence arguments."
            )

        selected_policy = intelligence_selection.policy
        provenance_selection = intelligence_selection

    else:
        if intelligence_trust is not None or intelligence_lifecycle is not None:
            raise ValueError(
                "Direct trust/lifecycle injection "
                "is disabled. Use the verified "
                "intelligence activation boundary."
            )

        selected_policy = intelligence_policy or default_policy()

        provenance_selection = None

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
        policy=selected_policy,
    )

    assessment_vendor = assessment.vendor_evidence

    cve_report = decide_cves(
        php_detected=assessment.php_detected,
        php_version=assessment.php_version,
        vendor_family=(assessment_vendor.vendor.value if assessment_vendor else None),
        backport_status=(assessment_vendor.backport_status.value if assessment_vendor else None),
        sapi_hypothesis=assessment.fingerprint.sapi.value,
        policy=selected_policy,
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

    findings = build_findings(
        target=target,
        assessment=assessment,
        cve_report=cve_report,
    )

    validate_cross_layer_consistency(
        assessment=assessment,
        cve_report=cve_report,
        findings=findings,
    )

    intelligence_identity = policy_identity(selected_policy)

    canonical_payload = {
        "target": target,
        "intelligence_policy": intelligence_identity,
        "http": metadata.model_dump(mode="json"),
        "assessment": assessment.model_dump(mode="json"),
        "cve_decisions": cve_report.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }

    target_identity_payload = {
        "requested_url": metadata.requested_url,
        "final_url": metadata.final_url,
        "server": metadata.server,
        "php_version": assessment.php_version,
        "body_sha256": metadata.body_sha256,
    }

    provenance = build_provenance(
        canonical_payload=canonical_payload,
        target_identity_payload=(target_identity_payload),
        intelligence_selection=(provenance_selection),
        intelligence_policy=(selected_policy if provenance_selection is None else None),
    )

    return UnifiedAssessmentReport(
        target=target,
        http=metadata,
        assessment=assessment,
        cve_decisions=cve_report,
        findings=findings,
        provenance=provenance,
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
