from __future__ import annotations

from pydantic import BaseModel


class EvidenceProvenance(BaseModel):
    report_id: str
    tool_name: str
    tool_version: str
    policy_version: str
    canonical_sha256: str
    target_identity_sha256: str
