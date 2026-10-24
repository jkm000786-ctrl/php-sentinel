from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from php_sentinel.intelligence.delegation import (
    resolve_verified_delegation_revocations,
)
from php_sentinel.intelligence.lifecycle import (
    bundled_lifecycle,
    evaluate_lifecycle,
    load_lifecycle_state,
    record_accepted_lifecycle,
    record_observed_delegation_revocations,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    load_policy,
)
from php_sentinel.intelligence.security_audit import (
    SecurityAuditStorageError,
    append_security_audit_event,
)
from php_sentinel.intelligence.state_key import (
    authority_state_key_path_for_state,
    load_or_create_authority_state_key,
)
from php_sentinel.intelligence.trust import (
    bundled_policy_trust,
    load_manifest,
    load_trust_store,
    verify_manifest,
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
from php_sentinel.models.security_audit import (
    SecurityAuditEvent,
    SecurityAuditEventType,
    SecurityAuditOutcome,
)


class IntelligenceActivationError(ValueError):
    """Raised when intelligence cannot be safely activated."""


_ACTIVATION_CAPABILITY = object()


class VerifiedIntelligenceSelection:
    """Verified policy/trust/lifecycle capability."""

    __slots__ = (
        "lifecycle",
        "policy",
        "trust",
    )

    def __init__(
        self,
        *,
        policy: IntelligencePolicy,
        trust: IntelligenceTrustDecision,
        lifecycle: IntelligenceLifecycleDecision,
        _capability: object | None = None,
    ) -> None:
        if _capability is not _ACTIVATION_CAPABILITY:
            raise TypeError("VerifiedIntelligenceSelection cannot be constructed directly.")

        if not trust.trusted:
            raise ValueError("Verified selection requires trusted intelligence.")

        if not lifecycle.activatable:
            raise ValueError("Verified selection requires activatable lifecycle.")

        self.policy = policy
        self.trust = trust
        self.lifecycle = lifecycle


def _verified_selection(
    *,
    policy: IntelligencePolicy,
    trust: IntelligenceTrustDecision,
    lifecycle: IntelligenceLifecycleDecision,
) -> VerifiedIntelligenceSelection:
    return VerifiedIntelligenceSelection(
        policy=policy,
        trust=trust,
        lifecycle=lifecycle,
        _capability=(_ACTIVATION_CAPABILITY),
    )


def activate_loaded_intelligence_with_lifecycle(
    *,
    policy: IntelligencePolicy,
    manifest,
    trust_store_path: Path | str,
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
    """
    Apply authoritative trust and lifecycle evaluation to already-loaded
    intelligence objects.

    The caller controls how policy and manifest bytes were obtained, but this
    function does not trust caller-supplied trust or lifecycle decisions.
    Current local trust and lifecycle authority are re-evaluated here.
    """

    try:
        trust_store = load_trust_store(trust_store_path)

        trust = verify_manifest(
            policy,
            manifest,
            trust_store,
            now=now,
        )

        if not trust.trusted:
            raise IntelligenceActivationError(
                f"External intelligence policy trust verification failed: {trust.state.value}."
            )

        state = None
        authority_key = None

        if lifecycle_state_path is not None:
            authority_key = load_or_create_authority_state_key(
                authority_state_key_path_for_state(lifecycle_state_path)
            )

            state = load_lifecycle_state(
                lifecycle_state_path,
                authority_key=authority_key,
                require_authenticated=True,
            )

        lifecycle_policy = IntelligenceLifecyclePolicy(
            minimum_generation=minimum_generation,
            maximum_age_days=maximum_age_days,
            maximum_future_skew_seconds=maximum_future_skew_seconds,
        )

        if lifecycle_state_path is not None:
            revocations = resolve_verified_delegation_revocations(
                trust_store=trust_store,
                successor_signer_id=manifest.signer_id,
                context="intelligence",
                now=now,
            )

            if revocations:
                state = record_observed_delegation_revocations(
                    path=lifecycle_state_path,
                    revocations=revocations,
                    expected_state=state,
                    now=now,
                    authority_key=authority_key,
                    require_authenticated=True,
                )

        lifecycle = evaluate_lifecycle(
            policy=policy,
            manifest=manifest,
            trust=trust,
            lifecycle_policy=lifecycle_policy,
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
                expected_state=state,
                now=now,
                authority_key=authority_key,
                require_authenticated=True,
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
        policy = load_policy(policy_path)
        manifest = load_manifest(manifest_path)
    except (
        OSError,
        ValueError,
    ) as exc:
        raise IntelligenceActivationError(
            f"External intelligence activation failed: {exc}"
        ) from exc

    return activate_loaded_intelligence_with_lifecycle(
        policy=policy,
        manifest=manifest,
        trust_store_path=trust_store_path,
        lifecycle_state_path=lifecycle_state_path,
        minimum_generation=minimum_generation,
        maximum_age_days=maximum_age_days,
        maximum_future_skew_seconds=maximum_future_skew_seconds,
        now=now,
    )


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


def activate_verified_intelligence(
    *,
    policy_path: Path | str | None = None,
    manifest_path: Path | str | None = None,
    trust_store_path: Path | str | None = None,
    lifecycle_state_path: Path | str | None = None,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> VerifiedIntelligenceSelection:
    (
        policy,
        trust,
        lifecycle,
    ) = activate_intelligence_with_lifecycle(
        policy_path=policy_path,
        manifest_path=manifest_path,
        trust_store_path=trust_store_path,
        lifecycle_state_path=(lifecycle_state_path),
        minimum_generation=(minimum_generation),
        maximum_age_days=(maximum_age_days),
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )

    return _verified_selection(
        policy=policy,
        trust=trust,
        lifecycle=lifecycle,
    )


def activate_verified_intelligence_objects(
    *,
    policy: IntelligencePolicy,
    manifest,
    trust_store_path: Path | str,
    lifecycle_state_path: Path | str | None = None,
    security_audit_path: Path | str | None = None,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> VerifiedIntelligenceSelection:
    (
        verified_policy,
        trust,
        lifecycle,
    ) = activate_loaded_intelligence_with_lifecycle(
        policy=policy,
        manifest=manifest,
        trust_store_path=trust_store_path,
        lifecycle_state_path=lifecycle_state_path,
        minimum_generation=minimum_generation,
        maximum_age_days=maximum_age_days,
        maximum_future_skew_seconds=maximum_future_skew_seconds,
        now=now,
    )

    selection = _verified_selection(
        policy=verified_policy,
        trust=trust,
        lifecycle=lifecycle,
    )

    if security_audit_path is not None:
        try:
            append_security_audit_event(
                security_audit_path,
                SecurityAuditEvent(
                    occurred_at=(now or datetime.now(UTC)),
                    event_type=(SecurityAuditEventType.INTELLIGENCE_ACTIVATION_ACCEPTED),
                    outcome=SecurityAuditOutcome.SUCCEEDED,
                    component="intelligence.activation",
                    operation="activate_verified_intelligence_objects",
                    policy_id=verified_policy.policy_id,
                    signer_id=manifest.signer_id,
                    generation=manifest.generation,
                    trust_state=trust.state.value,
                    lifecycle_state=lifecycle.state.value,
                ),
            )
        except SecurityAuditStorageError:
            pass

    return selection


def bundled_verified_intelligence() -> VerifiedIntelligenceSelection:
    return activate_verified_intelligence()
