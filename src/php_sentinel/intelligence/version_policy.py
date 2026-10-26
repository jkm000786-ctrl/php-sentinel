from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from php_sentinel.intelligence.repository import default_policy, fixed_version_for_branch
from php_sentinel.models.intelligence_policy import IntelligencePolicy


@dataclass(frozen=True)
class VersionDecision:
    known: bool
    upstream_supported_branch: bool
    upstream_fixed: bool | None
    requires_vendor_evidence: bool
    rationale: str


def evaluate_version(
    raw_version: str | None,
    *,
    policy: IntelligencePolicy | None = None,
) -> VersionDecision:
    if not raw_version:
        return VersionDecision(
            False,
            False,
            None,
            False,
            "No PHP version was disclosed; exposure cannot be decided from version policy.",
        )

    try:
        parsed = Version(raw_version)
    except InvalidVersion:
        return VersionDecision(
            False,
            False,
            None,
            True,
            "Version string could not be normalized; vendor/package evidence is required.",
        )

    release = parsed.release
    if len(release) < 2:
        return VersionDecision(False, False, None, True, "Incomplete PHP version.")

    branch = (release[0], release[1])
    selected_policy = policy or default_policy()
    threshold = fixed_version_for_branch(branch, policy=selected_policy)

    if threshold is None:
        return VersionDecision(
            True,
            False,
            None,
            True,
            f"PHP {raw_version} is outside directly modeled upstream branches; "
            "vendor backport evidence is required.",
        )

    fixed = parsed >= threshold

    if fixed:
        return VersionDecision(
            True,
            True,
            True,
            False,
            f"PHP {raw_version} meets upstream fixed threshold {threshold}.",
        )

    return VersionDecision(
        True,
        True,
        False,
        True,
        f"PHP {raw_version} is below upstream fixed threshold "
        f"{threshold}; this is not proof of exploitability "
        "because a vendor may have backported the fix.",
    )
