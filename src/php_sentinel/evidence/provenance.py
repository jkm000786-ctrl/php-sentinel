from __future__ import annotations

import hashlib
import json
from importlib.metadata import (
    PackageNotFoundError,
    version,
)
from uuid import uuid4

from php_sentinel.intelligence.activation import (
    VerifiedIntelligenceSelection,
)
from php_sentinel.intelligence.lifecycle import (
    resolve_lifecycle,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_identity,
)
from php_sentinel.intelligence.trust import (
    resolve_policy_trust,
)
from php_sentinel.models.edge import EdgeAssessment
from php_sentinel.models.edge_authority import EdgeAuthorityDecision
from php_sentinel.models.intelligence_lifecycle import (
    IntelligenceLifecycleDecision,
)
from php_sentinel.models.intelligence_policy import (
    IntelligencePolicy,
)
from php_sentinel.models.intelligence_trust import (
    IntelligenceTrustDecision,
)
from php_sentinel.models.provenance import (
    EvidenceProvenance,
)
from php_sentinel.models.transport import TransportEvidence

POLICY_VERSION = "2026-10-23.1"


def tool_version() -> str:
    try:
        return version("php-sentinel")
    except PackageNotFoundError:
        return "unknown"


VOLATILE_CANONICAL_FIELDS = {
    "generated_at",
    "observed_at",
    "report_id",
}


def _stable_payload(value):
    if isinstance(value, dict):
        return {
            key: _stable_payload(item)
            for key, item in value.items()
            if key not in VOLATILE_CANONICAL_FIELDS
        }

    if isinstance(value, list):
        return [_stable_payload(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_stable_payload(item) for item in value)

    return value


def _canonical_json(
    payload: dict,
) -> bytes:
    stable = _stable_payload(payload)

    return json.dumps(
        stable,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_payload(
    payload: dict,
) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def build_provenance(
    *,
    canonical_payload: dict,
    target_identity_payload: dict,
    edge_assessment: EdgeAssessment | None = None,
    edge_authority: EdgeAuthorityDecision | None = None,
    transport_evidence: TransportEvidence | None = None,
    intelligence_selection: VerifiedIntelligenceSelection | None = None,
    intelligence_policy: IntelligencePolicy | None = None,
    intelligence_trust: IntelligenceTrustDecision | None = None,
    intelligence_lifecycle: IntelligenceLifecycleDecision | None = None,
) -> EvidenceProvenance:
    if edge_authority is not None:
        if edge_assessment is None:
            raise ValueError(
                "Resolved edge authority requires the passive "
                "edge assessment it was derived from."
            )

        if edge_authority.passive != edge_assessment:
            raise ValueError(
                "Resolved edge authority passive observation "
                "does not match the supplied edge assessment."
            )

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
                "provenance arguments."
            )

        selected_policy = intelligence_selection.policy
        trust = intelligence_selection.trust
        lifecycle = intelligence_selection.lifecycle

    else:
        selected_policy = intelligence_policy or default_policy()

        trust = resolve_policy_trust(
            selected_policy,
            intelligence_trust,
        )

        lifecycle = resolve_lifecycle(
            policy=selected_policy,
            trust=trust,
            supplied=None,
        )

    identity = policy_identity(selected_policy)

    return EvidenceProvenance(
        report_id=str(uuid4()),
        tool_name="PHP Sentinel",
        tool_version=tool_version(),
        policy_version=POLICY_VERSION,
        canonical_sha256=sha256_payload(canonical_payload),
        target_identity_sha256=(sha256_payload(target_identity_payload)),
        edge_detected=(edge_assessment.edge_detected if edge_assessment else None),
        waf_detected=(edge_assessment.waf_detected if edge_assessment else None),
        edge_provider=(edge_assessment.provider.value if edge_assessment else None),
        edge_provider_confidence=(
            edge_assessment.provider_confidence if edge_assessment else None
        ),
        edge_provider_ambiguous=(
            edge_assessment.provider_ambiguous if edge_assessment else None
        ),
        edge_response_class=(
            edge_assessment.response_class.value if edge_assessment else None
        ),
        application_reachability=(
            edge_assessment.application_reachability.value
            if edge_assessment
            else None
        ),
        effective_edge_response_class=(
            edge_authority.effective_response_class.value
            if edge_authority
            else None
        ),
        effective_application_reachability=(
            edge_authority.effective_application_reachability.value
            if edge_authority
            else None
        ),
        waf_interception_established=(
            edge_authority.waf_interception_established
            if edge_authority
            else None
        ),
        edge_authority_constrained_by_differential=(
            edge_authority.constrained_by_differential
            if edge_authority
            else None
        ),
        differential_evidence_authority=(
            edge_authority.differential_evidence.authority.value
            if (
                edge_authority
                and edge_authority.differential_evidence
            )
            else None
        ),
        differential_edge_provider=(
            edge_authority.differential_evidence.provider.value
            if (
                edge_authority
                and edge_authority.differential_evidence
            )
            else None
        ),
        differential_protected_http_status=(
            edge_authority
            .differential_evidence
            .protected_http_status
            if (
                edge_authority
                and edge_authority.differential_evidence
            )
            else None
        ),
        differential_evidence_sha256=(
            edge_authority.differential_evidence.evidence_sha256
            if (
                edge_authority
                and edge_authority.differential_evidence
            )
            else None
        ),
        edge_challenge_detected=(
            edge_assessment.challenge_detected if edge_assessment else None
        ),
        edge_rate_limited=(
            edge_assessment.rate_limited if edge_assessment else None
        ),
        transport_attempts=(
            transport_evidence.execution.attempts
            if transport_evidence
            else None
        ),
        transport_requests_sent=(
            transport_evidence.execution.requests_sent
            if transport_evidence
            else None
        ),
        transport_retries=(
            transport_evidence.execution.retries
            if transport_evidence
            else None
        ),
        transport_budget_exhausted=(
            transport_evidence.execution.budget_exhausted
            if transport_evidence
            else None
        ),
        transport_retry_after_observed=(
            transport_evidence.execution.retry_after_observed
            if transport_evidence
            else None
        ),
        transport_retry_after_honored=(
            transport_evidence.execution.retry_after_honored
            if transport_evidence
            else None
        ),
        transport_rate_limit_observed=(
            transport_evidence.execution.rate_limit_observed
            if transport_evidence
            else None
        ),
        transport_redirect_target_denied=(
            transport_evidence.execution.redirect_target_denied
            if transport_evidence
            else None
        ),
        transport_stop_reason=(
            transport_evidence.execution.stop_reason.value
            if transport_evidence
            else None
        ),
        intelligence_policy_id=str(identity["policy_id"]),
        intelligence_schema_version=int(identity["schema_version"]),
        intelligence_published_date=str(identity["published_date"]),
        intelligence_sha256=str(identity["sha256"]),
        intelligence_trust_state=(trust.state.value),
        intelligence_signer_id=(trust.signer_id),
        intelligence_signature_algorithm=(trust.algorithm),
        intelligence_lifecycle_state=(lifecycle.state.value),
        intelligence_generation=(lifecycle.generation),
        intelligence_issued_at=(lifecycle.issued_at.isoformat() if lifecycle.issued_at else None),
        intelligence_expires_at=(
            lifecycle.expires_at.isoformat() if lifecycle.expires_at else None
        ),
    )
