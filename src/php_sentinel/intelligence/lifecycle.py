from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from php_sentinel.intelligence.repository import (
    policy_sha256,
)
from php_sentinel.models.intelligence_lifecycle import (
    IntelligenceLifecycleDecision,
    IntelligenceLifecyclePolicy,
    IntelligenceLifecycleState,
    LifecycleStateRecord,
    LifecycleStateStore,
)
from php_sentinel.models.intelligence_policy import (
    IntelligencePolicy,
)
from php_sentinel.models.intelligence_trust import (
    IntelligenceManifest,
    IntelligenceTrustDecision,
)

DEFAULT_LIFECYCLE_STATE_PATH = (
    Path.home() / ".local" / "state" / "php-sentinel" / "intelligence-lifecycle.json"
)


def bundled_lifecycle(
    policy: IntelligencePolicy,
) -> IntelligenceLifecycleDecision:
    return IntelligenceLifecycleDecision(
        state=IntelligenceLifecycleState.CURRENT,
        activatable=True,
        policy_id=policy.policy_id,
        policy_sha256=policy_sha256(policy),
        rationale=[
            (
                "Bundled intelligence lifecycle is "
                "governed by the installed PHP Sentinel "
                "package release."
            )
        ],
    )


def legacy_lifecycle(
    policy: IntelligencePolicy,
    trust: IntelligenceTrustDecision,
) -> IntelligenceLifecycleDecision:
    return IntelligenceLifecycleDecision(
        state=(IntelligenceLifecycleState.LEGACY_NO_LIFECYCLE),
        activatable=False,
        policy_id=policy.policy_id,
        policy_sha256=policy_sha256(policy),
        signer_id=trust.signer_id,
        rationale=[
            ("No validated lifecycle decision was supplied for this external intelligence.")
        ],
    )


def load_lifecycle_state(
    path: Path | str,
) -> LifecycleStateStore:
    state_path = Path(path)

    if not state_path.exists():
        return LifecycleStateStore()

    data = json.loads(state_path.read_text(encoding="utf-8"))

    return LifecycleStateStore.model_validate(data)


def save_lifecycle_state(
    path: Path | str,
    state: LifecycleStateStore,
) -> None:
    state_path = Path(path)

    state_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = state_path.with_suffix(state_path.suffix + ".tmp")

    temporary.write_text(
        json.dumps(
            state.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    temporary.replace(state_path)


def evaluate_lifecycle(
    *,
    policy: IntelligencePolicy,
    manifest: IntelligenceManifest,
    trust: IntelligenceTrustDecision,
    lifecycle_policy: (IntelligenceLifecyclePolicy | None) = None,
    state: LifecycleStateStore | None = None,
    now: datetime | None = None,
) -> IntelligenceLifecycleDecision:
    config = lifecycle_policy or IntelligenceLifecyclePolicy()

    current_time = now or datetime.now(UTC)

    digest = policy_sha256(policy)

    base = {
        "policy_id": policy.policy_id,
        "policy_sha256": digest,
        "generation": manifest.generation,
        "issued_at": manifest.issued_at,
        "expires_at": manifest.expires_at,
        "signer_id": trust.signer_id,
        "minimum_generation": (config.minimum_generation),
        "maximum_age_days": (config.maximum_age_days),
    }

    if not trust.trusted:
        return IntelligenceLifecycleDecision(
            state=(IntelligenceLifecycleState.LEGACY_NO_LIFECYCLE),
            activatable=False,
            **base,
            rationale=[
                ("Lifecycle acceptance cannot proceed because intelligence trust is not valid.")
            ],
        )

    if manifest.manifest_version < 2 or manifest.generation is None or manifest.expires_at is None:
        return IntelligenceLifecycleDecision(
            state=(IntelligenceLifecycleState.LEGACY_NO_LIFECYCLE),
            activatable=False,
            **base,
            rationale=[
                ("Legacy manifest lacks the lifecycle metadata required for safe activation.")
            ],
        )

    future_limit = current_time + timedelta(seconds=(config.maximum_future_skew_seconds))

    if manifest.issued_at > future_limit:
        return IntelligenceLifecycleDecision(
            state=(IntelligenceLifecycleState.FUTURE_ISSUED),
            activatable=False,
            **base,
            rationale=[("Manifest issued_at is too far in the future.")],
        )

    if current_time >= manifest.expires_at:
        return IntelligenceLifecycleDecision(
            state=(IntelligenceLifecycleState.EXPIRED),
            activatable=False,
            **base,
            rationale=["Manifest has expired."],
        )

    maximum_age = timedelta(days=config.maximum_age_days)

    if current_time - manifest.issued_at > maximum_age:
        return IntelligenceLifecycleDecision(
            state=(IntelligenceLifecycleState.STALE),
            activatable=False,
            **base,
            rationale=[("Manifest exceeds the maximum accepted intelligence age.")],
        )

    if manifest.generation < config.minimum_generation:
        return IntelligenceLifecycleDecision(
            state=(IntelligenceLifecycleState.BELOW_MINIMUM_GENERATION),
            activatable=False,
            **base,
            rationale=[
                ("Manifest generation is below the operator's minimum accepted generation.")
            ],
        )

    record = None

    if state is not None:
        record = state.records.get(policy.policy_id)

    if record is not None:
        if trust.signer_id != record.signer_id:
            rotation_authorized = (
                record.signer_id in (trust.authorized_predecessor_signer_ids)
                and manifest.generation > record.generation
            )

            if not rotation_authorized:
                return IntelligenceLifecycleDecision(
                    state=(IntelligenceLifecycleState.SIGNER_CHANGED),
                    activatable=False,
                    **base,
                    rationale=[
                        (
                            "Signer differs from the signer "
                            "pinned by the previously accepted "
                            "policy generation, and no valid "
                            "successor authorization was "
                            "established."
                        )
                    ],
                )

        if manifest.generation < record.generation:
            return IntelligenceLifecycleDecision(
                state=(IntelligenceLifecycleState.ROLLBACK_DETECTED),
                activatable=False,
                **base,
                rationale=[
                    (
                        "Manifest generation is lower than "
                        "the highest previously accepted "
                        "generation."
                    )
                ],
            )

        if manifest.generation == record.generation and digest != record.policy_sha256:
            return IntelligenceLifecycleDecision(
                state=(IntelligenceLifecycleState.REPLAY_DETECTED),
                activatable=False,
                **base,
                rationale=[
                    ("A different policy digest was presented for an already accepted generation.")
                ],
            )

    return IntelligenceLifecycleDecision(
        state=IntelligenceLifecycleState.CURRENT,
        activatable=True,
        **base,
        rationale=[
            (
                "Manifest signature, freshness, expiry, "
                "generation, signer pin, and rollback "
                "checks passed."
            )
        ],
    )


def record_accepted_lifecycle(
    *,
    path: Path | str,
    policy: IntelligencePolicy,
    lifecycle: IntelligenceLifecycleDecision,
    now: datetime | None = None,
) -> None:
    if not lifecycle.activatable or lifecycle.generation is None or lifecycle.signer_id is None:
        raise ValueError("Only an activatable external lifecycle decision can be recorded.")

    state = load_lifecycle_state(path)

    state.records[policy.policy_id] = LifecycleStateRecord(
        generation=lifecycle.generation,
        policy_sha256=(lifecycle.policy_sha256),
        signer_id=lifecycle.signer_id,
        accepted_at=(now or datetime.now(UTC)),
    )

    save_lifecycle_state(
        path,
        state,
    )


def resolve_lifecycle(
    *,
    policy: IntelligencePolicy,
    trust: IntelligenceTrustDecision,
    supplied: (IntelligenceLifecycleDecision | None) = None,
) -> IntelligenceLifecycleDecision:
    digest = policy_sha256(policy)

    if supplied is not None:
        if supplied.policy_id != policy.policy_id or supplied.policy_sha256 != digest:
            return IntelligenceLifecycleDecision(
                state=(IntelligenceLifecycleState.LEGACY_NO_LIFECYCLE),
                activatable=False,
                policy_id=policy.policy_id,
                policy_sha256=digest,
                signer_id=trust.signer_id,
                rationale=[("Supplied lifecycle decision does not match the intelligence policy.")],
            )

        return supplied

    if trust.state.value == "bundled_trusted":
        return bundled_lifecycle(policy)

    return legacy_lifecycle(
        policy,
        trust,
    )
