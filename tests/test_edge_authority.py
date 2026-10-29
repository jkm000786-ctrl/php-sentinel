from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from php_sentinel.assessment.edge_authority import resolve_edge_authority
from php_sentinel.models.edge import (
    ApplicationReachability,
    EdgeAssessment,
    EdgeProvider,
    EdgeResponseClass,
)
from php_sentinel.models.edge_authority import (
    EdgeAuthorityDecision,
    WAFDifferentialEvidence,
)

EVIDENCE_SHA256 = "a" * 64


def generic_403_passive() -> EdgeAssessment:
    return EdgeAssessment(
        edge_detected=False,
        waf_detected=False,
        provider=EdgeProvider.NONE,
        response_class=EdgeResponseClass.APPLICATION_RESPONSE,
        application_reachability=ApplicationReachability.PROBABLE,
        rationale=[
            "No supported edge or WAF fingerprint was established.",
        ],
    )


def differential_evidence() -> WAFDifferentialEvidence:
    return WAFDifferentialEvidence(
        provider=EdgeProvider.MODSECURITY,
        protected_http_status=403,
        evidence_sha256=EVIDENCE_SHA256,
        rationale=(
            "Backend correlation showed zero protected-path application hits.",
        ),
    )


def test_without_differential_evidence_preserves_generic_403_passive_state():
    passive = generic_403_passive()

    decision = resolve_edge_authority(passive)

    assert decision.passive == passive
    assert (
        decision.effective_response_class
        == EdgeResponseClass.APPLICATION_RESPONSE
    )
    assert (
        decision.effective_application_reachability
        == ApplicationReachability.PROBABLE
    )
    assert decision.waf_interception_established is False
    assert decision.constrained_by_differential is False
    assert decision.differential_evidence is None


def test_authorized_differential_evidence_constrains_generic_403_fail_closed():
    passive = generic_403_passive()
    evidence = differential_evidence()

    decision = resolve_edge_authority(
        passive,
        differential_evidence=evidence,
    )

    assert decision.passive == passive
    assert passive.response_class == EdgeResponseClass.APPLICATION_RESPONSE
    assert (
        passive.application_reachability
        == ApplicationReachability.PROBABLE
    )

    assert decision.effective_response_class == EdgeResponseClass.WAF_BLOCK
    assert (
        decision.effective_application_reachability
        == ApplicationReachability.NOT_REACHED
    )
    assert decision.waf_interception_established is True
    assert decision.constrained_by_differential is True
    assert decision.differential_evidence == evidence


def test_explicit_passive_waf_block_remains_authoritative_without_differential():
    passive = EdgeAssessment(
        edge_detected=False,
        waf_detected=True,
        provider=EdgeProvider.MODSECURITY,
        response_class=EdgeResponseClass.WAF_BLOCK,
        application_reachability=ApplicationReachability.NOT_REACHED,
    )

    decision = resolve_edge_authority(passive)

    assert decision.effective_response_class == EdgeResponseClass.WAF_BLOCK
    assert (
        decision.effective_application_reachability
        == ApplicationReachability.NOT_REACHED
    )
    assert decision.waf_interception_established is True
    assert decision.constrained_by_differential is False


def test_differential_evidence_rejects_provider_none():
    with pytest.raises(
        ValidationError,
        match="cannot use provider=none",
    ):
        WAFDifferentialEvidence(
            provider=EdgeProvider.NONE,
            protected_http_status=403,
            evidence_sha256=EVIDENCE_SHA256,
        )


def test_differential_evidence_cannot_claim_protected_application_reached():
    with pytest.raises(ValidationError):
        WAFDifferentialEvidence(
            provider=EdgeProvider.MODSECURITY,
            protected_application_reached=True,
            protected_http_status=403,
            evidence_sha256=EVIDENCE_SHA256,
        )


def test_differential_evidence_requires_canonical_sha256():
    with pytest.raises(ValidationError):
        WAFDifferentialEvidence(
            provider=EdgeProvider.MODSECURITY,
            protected_http_status=403,
            evidence_sha256="not-a-sha256",
        )


def test_authority_model_rejects_effective_state_mutation_without_evidence():
    passive = generic_403_passive()

    with pytest.raises(
        ValidationError,
        match="effective response class",
    ):
        EdgeAuthorityDecision(
            passive=passive,
            effective_response_class=EdgeResponseClass.WAF_BLOCK,
            effective_application_reachability=ApplicationReachability.PROBABLE,
        )


def test_authority_resolution_is_deterministic_and_contains_no_timestamp():
    decision = resolve_edge_authority(
        generic_403_passive(),
        differential_evidence=differential_evidence(),
    )

    first = decision.model_dump_json()
    second = decision.model_dump_json()

    assert first == second

    payload = json.loads(first)

    assert "generated_at" not in payload
    assert "observed_at" not in payload
    assert (
        payload["differential_evidence"]["evidence_sha256"]
        == EVIDENCE_SHA256
    )
