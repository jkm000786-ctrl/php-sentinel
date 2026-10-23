from __future__ import annotations

import hashlib
import json
from importlib.metadata import PackageNotFoundError, version
from uuid import uuid4

from php_sentinel.models.provenance import EvidenceProvenance

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


def _canonical_json(payload: dict) -> bytes:
    stable = _stable_payload(payload)

    return json.dumps(
        stable,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_payload(payload: dict) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def build_provenance(
    *,
    canonical_payload: dict,
    target_identity_payload: dict,
) -> EvidenceProvenance:
    return EvidenceProvenance(
        report_id=str(uuid4()),
        tool_name="PHP Sentinel",
        tool_version=tool_version(),
        policy_version=POLICY_VERSION,
        canonical_sha256=sha256_payload(canonical_payload),
        target_identity_sha256=sha256_payload(target_identity_payload),
    )
