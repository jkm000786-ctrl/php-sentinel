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
    edge_challenge_detected: bool | None = None
    edge_rate_limited: bool | None = None

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
