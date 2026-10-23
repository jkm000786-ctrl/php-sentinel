from __future__ import annotations

from pathlib import Path

from php_sentinel.intelligence.repository import (
    default_policy,
)
from php_sentinel.intelligence.trust import (
    bundled_policy_trust,
    load_verified_external_policy,
)
from php_sentinel.models.intelligence_policy import (
    IntelligencePolicy,
)
from php_sentinel.models.intelligence_trust import (
    IntelligenceTrustDecision,
)


class IntelligenceActivationError(ValueError):
    """Raised when intelligence cannot be safely activated."""


def activate_intelligence(
    *,
    policy_path: Path | str | None = None,
    manifest_path: Path | str | None = None,
    trust_store_path: Path | str | None = None,
) -> tuple[
    IntelligencePolicy,
    IntelligenceTrustDecision,
]:
    supplied = (
        policy_path,
        manifest_path,
        trust_store_path,
    )

    if not any(item is not None for item in supplied):
        policy = default_policy()

        return (
            policy,
            bundled_policy_trust(policy),
        )

    if not all(item is not None for item in supplied):
        raise IntelligenceActivationError(
            "External intelligence activation "
            "requires --policy, --manifest, and "
            "--trust-store together. Unsigned or "
            "partially specified external policies "
            "are not activated."
        )

    try:
        return load_verified_external_policy(
            policy_path=policy_path,
            manifest_path=manifest_path,
            trust_store_path=trust_store_path,
        )
    except (
        OSError,
        ValueError,
    ) as exc:
        raise IntelligenceActivationError(
            f"External intelligence activation failed: {exc}"
        ) from exc
