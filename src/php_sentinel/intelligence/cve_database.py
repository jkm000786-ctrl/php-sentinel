from dataclasses import dataclass

from php_sentinel.intelligence.repository import (
    default_policy,
)


@dataclass(frozen=True)
class PHPAdvisory:
    cve: str
    description: str


def _legacy_database_snapshot():
    policy = default_policy()

    advisories = tuple(
        PHPAdvisory(
            cve=item.cve_id,
            description=item.description,
        )
        for item in policy.cves
    )

    fixed_upstream = {
        tuple(int(part) for part in branch.split(".")): tuple(
            int(part) for part in version.split(".")
        )
        for branch, version in policy.fixed_versions.items()
    }

    return advisories, fixed_upstream


OCT_2026_CRITICAL, FIXED_UPSTREAM = _legacy_database_snapshot()
