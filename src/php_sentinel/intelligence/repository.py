from __future__ import annotations

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


def _read_default_policy() -> str:
    resource = resources.files("php_sentinel").joinpath(DEFAULT_POLICY_RESOURCE)

    return resource.read_text(encoding="utf-8")


def load_policy(
    path: Path | str | None = None,
) -> IntelligencePolicy:
    if path is None:
        raw = _read_default_policy()
    else:
        raw = Path(path).read_text(encoding="utf-8")

    data = json.loads(raw)

    return IntelligencePolicy.model_validate(data)


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
