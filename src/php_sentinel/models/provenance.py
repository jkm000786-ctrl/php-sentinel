from __future__ import annotations

from pydantic import BaseModel


class EvidenceProvenance(BaseModel):
    report_id: str
    tool_name: str
    tool_version: str

    policy_version: str

    canonical_sha256: str
    target_identity_sha256: str

    intelligence_policy_id: str | None = None
    intelligence_schema_version: int | None = None
    intelligence_published_date: str | None = None
    intelligence_sha256: str | None = None

    # Phase 13 trust provenance.
    intelligence_trust_state: str | None = None
    intelligence_signer_id: str | None = None
    intelligence_signature_algorithm: str | None = None
