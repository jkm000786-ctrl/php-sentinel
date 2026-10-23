import httpx

from php_sentinel.detection.php_detector import detect_php
from php_sentinel.intelligence.cve_database import OCT_2026_CRITICAL
from php_sentinel.intelligence.version_policy import evaluate_version
from php_sentinel.models.assessment import Assessment, AssessmentStatus
from php_sentinel.models.evidence import Confidence, Evidence, EvidenceKind


def assess_response(target: str, response: httpx.Response) -> Assessment:
    detection = detect_php(response)

    result = Assessment(
        target=target,
        php_detected=detection.detected,
        php_version=detection.version,
        server=detection.server,
        x_powered_by=detection.x_powered_by,
    )
    result.rationale.extend(detection.reasons)

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
        return result

    policy = evaluate_version(detection.version)
    result.rationale.append(policy.rationale)

    if policy.upstream_fixed is True:
        result.status = AssessmentStatus.PATCHED_UPSTREAM
        return result

    if policy.requires_vendor_evidence:
        result.status = AssessmentStatus.NEEDS_VENDOR_EVIDENCE
        result.applicable_cves = [x.cve for x in OCT_2026_CRITICAL]
        return result

    return result
