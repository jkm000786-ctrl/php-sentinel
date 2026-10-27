from __future__ import annotations

import hashlib

import httpx

from php_sentinel.assessment.consistency import validate_cross_layer_consistency
from php_sentinel.assessment.exposure import assess_response
from php_sentinel.assessment.finding_engine import build_findings
from php_sentinel.detection.edge_detector import classify_edge_response
from php_sentinel.evidence.provenance import build_provenance
from php_sentinel.http.client import fetch_with_transport
from php_sentinel.intelligence.activation import (
    VerifiedIntelligenceSelection,
)
from php_sentinel.intelligence.cve_decision_engine import decide_cves
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_identity,
)
from php_sentinel.models.assessment import Assessment, AssessmentStatus
from php_sentinel.models.cve_decision import (
    CVEDecisionStatus,
    DecisionConfidence,
    ExposurePriority,
)
from php_sentinel.models.edge import (
    ApplicationReachability,
    EdgeAssessment,
    EdgeResponseClass,
)
from php_sentinel.models.intelligence_lifecycle import IntelligenceLifecycleDecision
from php_sentinel.models.intelligence_policy import IntelligencePolicy
from php_sentinel.models.intelligence_trust import IntelligenceTrustDecision
from php_sentinel.models.transport import (
    TransportEvidence,
    TransportExecution,
    TransportStopReason,
)
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


def _edge_blocks_application_assessment(
    edge_assessment: EdgeAssessment,
) -> bool:
    return (
        edge_assessment.response_class
        != EdgeResponseClass.APPLICATION_RESPONSE
        or edge_assessment.application_reachability
        in {
            ApplicationReachability.UNKNOWN,
            ApplicationReachability.NOT_REACHED,
        }
    )


def _build_edge_inconclusive_assessment(
    *,
    target: str,
    response,
    edge_assessment: EdgeAssessment,
) -> Assessment:
    reason = (
        "Application-layer assessment suppressed because the observed "
        f"response class is {edge_assessment.response_class.value} and "
        "application reachability is "
        f"{edge_assessment.application_reachability.value}."
    )

    return Assessment(
        target=target,
        php_detected=False,
        php_version=None,
        php_confidence=0.0,
        server=response.headers.get("server"),
        x_powered_by=None,
        exposure_priority=ExposurePriority.UNKNOWN.value,
        status=AssessmentStatus.INCONCLUSIVE,
        applicable_cves=[],
        rationale=[*edge_assessment.rationale, reason],
        remediation=[
            (
                "Obtain a permitted application-layer response before "
                "drawing PHP runtime or CVE applicability conclusions."
            )
        ],
    )


def _normalize_transport_result(
    result: tuple[httpx.Response, TransportEvidence] | httpx.Response,
) -> tuple[httpx.Response, TransportEvidence]:
    if isinstance(result, tuple):
        return result

    response = result

    return (
        response,
        TransportEvidence(
            execution=TransportExecution(
                attempts=1,
                requests_sent=1,
                redirect_count=len(response.history),
            )
        ),
    )


def _transport_blocks_application_assessment(
    transport_evidence: TransportEvidence,
) -> bool:
    return (
        transport_evidence.execution.stop_reason
        != TransportStopReason.COMPLETED
    )


def _build_transport_inconclusive_assessment(
    *,
    target: str,
    response: httpx.Response,
    transport_evidence: TransportEvidence,
) -> Assessment:
    stop_reason = transport_evidence.execution.stop_reason.value

    reason = (
        "Application-layer assessment suppressed because transport "
        f"execution stopped with {stop_reason}."
    )

    return Assessment(
        target=target,
        php_detected=False,
        php_version=None,
        php_confidence=0.0,
        server=response.headers.get("server"),
        x_powered_by=None,
        exposure_priority=ExposurePriority.UNKNOWN.value,
        status=AssessmentStatus.INCONCLUSIVE,
        applicable_cves=[],
        rationale=[reason],
        remediation=[
            (
                "Resolve the transport-policy stop condition and obtain "
                "a completed permitted application response before "
                "drawing PHP runtime or CVE applicability conclusions."
            )
        ],
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

    response, transport_evidence = _normalize_transport_result(
        fetch_with_transport(
            target,
            timeout=timeout,
        )
    )

    edge_assessment = classify_edge_response(response)

    transport_application_suppressed = (
        _transport_blocks_application_assessment(
            transport_evidence
        )
    )
    edge_application_suppressed = (
        _edge_blocks_application_assessment(
            edge_assessment
        )
    )

    if (
        transport_application_suppressed
        or edge_application_suppressed
    ):
        if transport_application_suppressed:
            assessment = _build_transport_inconclusive_assessment(
                target=target,
                response=response,
                transport_evidence=transport_evidence,
            )

            gate_reason = (
                "CVE applicability is inconclusive because transport "
                "execution did not complete successfully. Stop reason: "
                f"{transport_evidence.execution.stop_reason.value}."
            )

            gate_remediation = (
                "Resolve the transport-policy stop condition and obtain "
                "a completed permitted application response before "
                "evaluating this CVE."
            )

        else:
            assessment = _build_edge_inconclusive_assessment(
                target=target,
                response=response,
                edge_assessment=edge_assessment,
            )

            gate_reason = (
                "CVE applicability is inconclusive because PHP Sentinel "
                "did not establish application-layer reachability."
            )

            gate_remediation = (
                "Obtain a permitted application-layer response "
                "before evaluating this CVE."
            )

        seed_report = decide_cves(
            php_detected=True,
            php_version=None,
            vendor_family=None,
            backport_status=None,
            sapi_hypothesis="unknown",
            policy=selected_policy,
        )

        decisions = [
            decision.model_copy(
                update={
                    "status": CVEDecisionStatus.INCONCLUSIVE,
                    "confidence": DecisionConfidence.LOW,
                    "exposure_priority": ExposurePriority.UNKNOWN,
                    "detected_version": None,
                    "rationale": [
                        gate_reason,
                        *decision.rationale,
                    ],
                    "remediation": [
                        gate_remediation,
                    ],
                }
            )
            for decision in seed_report.decisions
        ]

        cve_report = seed_report.model_copy(
            update={
                "php_detected": False,
                "php_version": None,
                "vendor_family": None,
                "backport_status": None,
                "sapi_hypothesis": "unknown",
                "decisions": decisions,
                "notes": [
                    *seed_report.notes,
                    gate_reason,
                ],
            }
        )

    else:
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
            vendor_family=(
                assessment_vendor.vendor.value
                if assessment_vendor
                else None
            ),
            backport_status=(
                assessment_vendor.backport_status.value
                if assessment_vendor
                else None
            ),
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
        edge_assessment=edge_assessment,
    )

    validate_cross_layer_consistency(
        assessment=assessment,
        cve_report=cve_report,
        findings=findings,
        edge_assessment=edge_assessment,
        transport_evidence=transport_evidence,
    )

    intelligence_identity = policy_identity(selected_policy)

    canonical_payload = {
        "target": target,
        "intelligence_policy": intelligence_identity,
        "http": metadata.model_dump(mode="json"),
        "transport": transport_evidence.model_dump(mode="json"),
        "edge": edge_assessment.model_dump(mode="json"),
        "assessment": assessment.model_dump(mode="json"),
        "cve_decisions": cve_report.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }

    target_identity_payload = {
        "requested_url": metadata.requested_url,
        "final_url": metadata.final_url,
        "server": metadata.server,
        "php_version": assessment.php_version,
        "edge_provider": edge_assessment.provider.value,
        "edge_response_class": edge_assessment.response_class.value,
        "application_reachability": (
            edge_assessment.application_reachability.value
        ),
        "body_sha256": metadata.body_sha256,
    }

    provenance = build_provenance(
        canonical_payload=canonical_payload,
        target_identity_payload=(target_identity_payload),
        edge_assessment=edge_assessment,
        transport_evidence=transport_evidence,
        intelligence_selection=(provenance_selection),
        intelligence_policy=(selected_policy if provenance_selection is None else None),
    )

    return UnifiedAssessmentReport(
        target=target,
        http=metadata,
        transport=transport_evidence,
        edge=edge_assessment,
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
            (
                "Edge/WAF observations are authoritative constraints on "
                "whether application evidence may be interpreted."
            ),
            ("CVE applicability is not equivalent to successful exploitation."),
        ],
    )
