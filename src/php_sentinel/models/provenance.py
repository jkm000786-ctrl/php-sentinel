from __future__ import annotations

from pydantic import BaseModel


class EvidenceProvenance(BaseModel):
    report_id: str
    tool_name: str
    tool_version: str
    policy_version: str

    canonical_sha256: str
    target_identity_sha256: str

    edge_detected: bool | None = None
    waf_detected: bool | None = None
    edge_provider: str | None = None
    edge_provider_confidence: float | None = None
    edge_provider_ambiguous: bool | None = None
    edge_response_class: str | None = None
    application_reachability: str | None = None

    effective_edge_response_class: str | None = None
    effective_application_reachability: str | None = None
    waf_interception_established: bool | None = None
    edge_authority_constrained_by_differential: bool | None = None
    differential_evidence_authority: str | None = None
    differential_edge_provider: str | None = None
    differential_protected_http_status: int | None = None
    differential_evidence_sha256: str | None = None

    edge_challenge_detected: bool | None = None
    edge_rate_limited: bool | None = None

    transport_attempts: int | None = None
    transport_requests_sent: int | None = None
    transport_retries: int | None = None
    transport_budget_exhausted: bool | None = None
    transport_retry_after_observed: bool | None = None
    transport_retry_after_honored: bool | None = None
    transport_rate_limit_observed: bool | None = None
    transport_redirect_target_denied: bool | None = None
    transport_stop_reason: str | None = None

    intelligence_policy_id: str | None = None
    intelligence_schema_version: int | None = None
    intelligence_published_date: str | None = None
    intelligence_sha256: str | None = None

    intelligence_trust_state: str | None = None
    intelligence_signer_id: str | None = None
    intelligence_signature_algorithm: str | None = None

    # Phase 15 lifecycle provenance.
    intelligence_lifecycle_state: str | None = None
    intelligence_generation: int | None = None
    intelligence_issued_at: str | None = None
    intelligence_expires_at: str | None = None
