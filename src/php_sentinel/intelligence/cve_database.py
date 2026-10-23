from dataclasses import dataclass

from php_sentinel.intelligence.repository import (
    default_policy,
)


@dataclass(frozen=True)
class PHPAdvisory:
    cve: str
    description: str


_POLICY = default_policy()


OCT_2026_CRITICAL = tuple(
    PHPAdvisory(
        cve=item.cve_id,
        description=item.description,
    )
    for item in _POLICY.cves
)


FIXED_UPSTREAM = {
    tuple(int(part) for part in branch.split(".")): tuple(int(part) for part in version.split("."))
    for branch, version in _POLICY.fixed_versions.items()
}
