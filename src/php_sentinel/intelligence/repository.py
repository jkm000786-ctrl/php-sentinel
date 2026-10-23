from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from importlib import resources
from pathlib import Path

from packaging.version import Version

from php_sentinel.models.intelligence_policy import (
    CVEPolicy,
    IntelligencePolicy,
)

DEFAULT_POLICY_RESOURCE = "data/intelligence/php-2026-10-critical.json"

SUPPORTED_SCHEMA_VERSIONS = frozenset({1})


def _read_default_policy() -> str:
    resource = resources.files("php_sentinel").joinpath(DEFAULT_POLICY_RESOURCE)

    return resource.read_text(encoding="utf-8")


def canonical_policy_bytes(
    policy: IntelligencePolicy,
) -> bytes:
    payload = policy.model_dump(mode="json")

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def policy_sha256(
    policy: IntelligencePolicy,
) -> str:
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def policy_identity(
    policy: IntelligencePolicy,
) -> dict[str, str | int]:
    return {
        "policy_id": policy.policy_id,
        "schema_version": policy.schema_version,
        "published_date": str(policy.published_date),
        "sha256": policy_sha256(policy),
    }


def _validate_supported_schema(
    policy: IntelligencePolicy,
) -> IntelligencePolicy:
    if policy.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(str(item) for item in sorted(SUPPORTED_SCHEMA_VERSIONS))

        raise ValueError(
            "Unsupported intelligence policy "
            f"schema_version={policy.schema_version}. "
            f"Supported schema versions: {supported}."
        )

    return policy


def load_policy(
    path: Path | str | None = None,
) -> IntelligencePolicy:
    if path is None:
        raw = _read_default_policy()
    else:
        raw = Path(path).read_text(encoding="utf-8")

    data = json.loads(raw)

    policy = IntelligencePolicy.model_validate(data)

    return _validate_supported_schema(policy)


@lru_cache(maxsize=1)
def default_policy() -> IntelligencePolicy:
    return load_policy()


def fixed_version_for_branch(
    branch: tuple[int, int],
    *,
    policy: IntelligencePolicy | None = None,
) -> Version | None:
    selected = policy or default_policy()

    raw = selected.fixed_versions.get(f"{branch[0]}.{branch[1]}")

    if raw is None:
        return None

    return Version(raw)


def cve_by_id(
    cve_id: str,
    *,
    policy: IntelligencePolicy | None = None,
) -> CVEPolicy | None:
    selected = policy or default_policy()

    for item in selected.cves:
        if item.cve_id == cve_id:
            return item

    return None
