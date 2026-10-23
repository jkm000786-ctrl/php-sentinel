from __future__ import annotations

import httpx

from php_sentinel.detection.confidence import calculate_php_confidence
from php_sentinel.detection.php_detector import detect_php
from php_sentinel.detection.sapi_detector import infer_sapi
from php_sentinel.detection.server_detector import detect_server_family
from php_sentinel.intelligence.applicability import evaluate_oct_2026_applicability
from php_sentinel.intelligence.backport_analyzer import analyze_backport
from php_sentinel.intelligence.remediation import remediation_for
from php_sentinel.intelligence.version_policy import evaluate_version
from php_sentinel.models.assessment import Assessment, AssessmentStatus
from php_sentinel.models.evidence import Confidence, Evidence, EvidenceKind
from php_sentinel.models.fingerprint import Fingerprint
from php_sentinel.models.vendor import VendorEvidence


def assess_response(
    target: str,
    response: httpx.Response,
    vendor_evidence: VendorEvidence | None = None,
) -> Assessment:
    detection = detect_php(response)
    body = response.text[:200_000]

    server_family = detect_server_family(detection.server)

    sapi = infer_sapi(
        server_family=server_family,
        server_header=detection.server,
        x_powered_by=detection.x_powered_by,
        body=body,
    )

    body_lower = body.lower()

    body_php_marker = "php" in body_lower and any(
        marker.lower() in body_lower
        for marker in (
            "Fatal error:",
            "Parse error:",
            "PHP Version",
            "PHP_SAPI",
            "sapi=",
        )
    )

    php_confidence = calculate_php_confidence(
        php_detected=detection.detected,
        version_known=detection.version is not None,
        x_powered_by_present=detection.x_powered_by is not None,
        body_php_marker=body_php_marker,
    )

    result = Assessment(
        target=target,
        php_detected=detection.detected,
        php_version=detection.version,
        server=detection.server,
        x_powered_by=detection.x_powered_by,
        vendor_evidence=vendor_evidence,
    )

    result.fingerprint = Fingerprint(
        server_family=server_family,
        server_raw=detection.server,
        sapi=sapi.sapi,
        sapi_confidence=sapi.confidence,
        indicators=list(sapi.indicators),
    )

    result.php_confidence = php_confidence
    result.rationale.extend(detection.reasons)
    result.rationale.extend(sapi.indicators)

    if detection.server:
        result.evidence.append(
            Evidence(
                kind=EvidenceKind.HTTP_HEADER,
                source="Server",
                value=detection.server,
                confidence=Confidence.MEDIUM,
            )
        )

    if detection.x_powered_by:
        result.evidence.append(
            Evidence(
                kind=EvidenceKind.HTTP_HEADER,
                source="X-Powered-By",
                value=detection.x_powered_by,
                confidence=Confidence.HIGH,
            )
        )

    if not detection.detected:
        result.status = AssessmentStatus.NOT_PHP
        result.rationale.append("No sufficiently strong PHP indicator was observed.")
        result.remediation = list(remediation_for(result.status))
        return result

    policy = evaluate_version(detection.version)
    result.rationale.append(policy.rationale)

    applicability = evaluate_oct_2026_applicability(
        php_detected=detection.detected,
        upstream_fixed=policy.upstream_fixed,
        sapi=sapi.sapi,
    )

    result.exposure_priority = applicability.exposure_priority
    result.rationale.extend(applicability.rationale)

    if policy.upstream_fixed is True:
        result.status = AssessmentStatus.PATCHED_UPSTREAM
        result.remediation = list(remediation_for(result.status))
        return result

    if applicability.applicable:
        result.applicable_cves = list(applicability.cves)

    backport = analyze_backport(vendor_evidence)
    result.rationale.extend(backport.rationale)

    if backport.fixed_by_vendor is True:
        result.status = AssessmentStatus.PATCHED_VENDOR
        result.applicable_cves = []
        result.remediation = list(remediation_for(result.status))
        return result

    if backport.fixed_by_vendor is False:
        result.status = AssessmentStatus.POTENTIALLY_AFFECTED
        result.remediation = list(remediation_for(result.status))
        return result

    if policy.requires_vendor_evidence:
        result.status = AssessmentStatus.NEEDS_VENDOR_EVIDENCE
        result.remediation = list(remediation_for(result.status))
        return result

    result.status = AssessmentStatus.INCONCLUSIVE
    result.remediation = list(remediation_for(result.status))
    return result
