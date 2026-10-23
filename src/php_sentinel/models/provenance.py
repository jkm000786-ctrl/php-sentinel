from __future__ import annotations

from pydantic import BaseModel


class EvidenceProvenance(BaseModel):
    report_id: str
    tool_name: str
    tool_version: str

    # PHP Sentinel deterministic decision-policy version.
    policy_version: str

    canonical_sha256: str
    target_identity_sha256: str

    # Intelligence-policy provenance.
    #
    # Optional for backward compatibility with reports generated
    # before Phase 12.
    intelligence_policy_id: str | None = None
    intelligence_schema_version: int | None = None
    intelligence_published_date: str | None = None
    intelligence_sha256: str | None = None
