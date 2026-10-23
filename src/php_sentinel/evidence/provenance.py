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
    intelligence_selection: VerifiedIntelligenceSelection | None = None,
    intelligence_policy: IntelligencePolicy | None = None,
    intelligence_trust: IntelligenceTrustDecision | None = None,
    intelligence_lifecycle: IntelligenceLifecycleDecision | None = None,
) -> EvidenceProvenance:
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
