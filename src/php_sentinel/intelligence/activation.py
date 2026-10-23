from __future__ import annotations

from datetime import datetime
from pathlib import Path

from php_sentinel.intelligence.lifecycle import (
    bundled_lifecycle,
    evaluate_lifecycle,
    load_lifecycle_state,
    record_accepted_lifecycle,
)
from php_sentinel.intelligence.repository import (
    default_policy,
)
from php_sentinel.intelligence.trust import (
    bundled_policy_trust,
    load_verified_external_bundle,
)
from php_sentinel.models.intelligence_lifecycle import (
    IntelligenceLifecycleDecision,
    IntelligenceLifecyclePolicy,
)
from php_sentinel.models.intelligence_policy import (
    IntelligencePolicy,
)
from php_sentinel.models.intelligence_trust import (
    IntelligenceTrustDecision,
)


class IntelligenceActivationError(ValueError):
    """Raised when intelligence cannot be safely activated."""


def activate_intelligence_with_lifecycle(
    *,
    policy_path: Path | str | None = None,
    manifest_path: Path | str | None = None,
    trust_store_path: Path | str | None = None,
    lifecycle_state_path: Path | str | None = None,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> tuple[
    IntelligencePolicy,
    IntelligenceTrustDecision,
    IntelligenceLifecycleDecision,
]:
    supplied = (
        policy_path,
        manifest_path,
        trust_store_path,
    )

    if not any(item is not None for item in supplied):
        policy = default_policy()
        trust = bundled_policy_trust(policy)
        lifecycle = bundled_lifecycle(policy)

        return (
            policy,
            trust,
            lifecycle,
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
        (
            policy,
            manifest,
            trust,
        ) = load_verified_external_bundle(
            policy_path=policy_path,
            manifest_path=manifest_path,
            trust_store_path=trust_store_path,
        )

        state = None

        if lifecycle_state_path is not None:
            state = load_lifecycle_state(lifecycle_state_path)

        lifecycle = evaluate_lifecycle(
            policy=policy,
            manifest=manifest,
            trust=trust,
            lifecycle_policy=(
                IntelligenceLifecyclePolicy(
                    minimum_generation=(minimum_generation),
                    maximum_age_days=(maximum_age_days),
                    maximum_future_skew_seconds=(maximum_future_skew_seconds),
                )
            ),
            state=state,
            now=now,
        )

        if not lifecycle.activatable:
            raise IntelligenceActivationError(
                f"External intelligence lifecycle check failed: {lifecycle.state.value}."
            )

        if lifecycle_state_path is not None:
            record_accepted_lifecycle(
                path=lifecycle_state_path,
                policy=policy,
                lifecycle=lifecycle,
                now=now,
            )

        return (
            policy,
            trust,
            lifecycle,
        )

    except IntelligenceActivationError:
        raise
    except (
        OSError,
        ValueError,
    ) as exc:
        raise IntelligenceActivationError(
            f"External intelligence activation failed: {exc}"
        ) from exc


def activate_intelligence(
    *,
    policy_path: Path | str | None = None,
    manifest_path: Path | str | None = None,
    trust_store_path: Path | str | None = None,
    lifecycle_state_path: Path | str | None = None,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> tuple[
    IntelligencePolicy,
    IntelligenceTrustDecision,
]:
    (
        policy,
        trust,
        _,
    ) = activate_intelligence_with_lifecycle(
        policy_path=policy_path,
        manifest_path=manifest_path,
        trust_store_path=trust_store_path,
        lifecycle_state_path=lifecycle_state_path,
        minimum_generation=minimum_generation,
        maximum_age_days=maximum_age_days,
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )

    return policy, trust
