from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
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


class LifecycleStateStorageError(ValueError):
    """Raised when lifecycle rollback state cannot be handled safely."""


LIFECYCLE_STATE_DIRECTORY_MODE = 0o700
LIFECYCLE_STATE_FILE_MODE = 0o600

LIFECYCLE_LOCK_TIMEOUT_SECONDS = 5.0
LIFECYCLE_LOCK_POLL_SECONDS = 0.05
LIFECYCLE_STALE_LOCK_SECONDS = 30.0


def _secure_directory(
    directory: Path,
) -> None:
    directory.mkdir(
        parents=True,
        exist_ok=True,
        mode=LIFECYCLE_STATE_DIRECTORY_MODE,
    )

    try:
        directory.chmod(LIFECYCLE_STATE_DIRECTORY_MODE)
    except OSError:
        # Some filesystems/platforms cannot enforce POSIX mode bits.
        # Storage still fails on actual read/write errors.
        pass


def _secure_file(
    path: Path,
) -> None:
    try:
        path.chmod(LIFECYCLE_STATE_FILE_MODE)
    except OSError:
        # Best-effort on non-POSIX filesystems.
        pass


def _directory_fsync(
    directory: Path,
) -> None:
    flags = os.O_RDONLY

    if hasattr(
        os,
        "O_DIRECTORY",
    ):
        flags |= os.O_DIRECTORY

    try:
        descriptor = os.open(
            directory,
            flags,
        )
    except OSError:
        # Directory fsync is not available on every platform/filesystem.
        return

    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _lock_path(
    state_path: Path,
) -> Path:
    return state_path.with_suffix(state_path.suffix + ".lock")


def _temporary_path(
    state_path: Path,
) -> Path:
    return state_path.with_suffix(state_path.suffix + ".tmp")


def _lock_owner_is_alive(
    lock_path: Path,
) -> bool:
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))

        pid = int(data["pid"])

    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return False

    if pid <= 0:
        return False

    try:
        os.kill(
            pid,
            0,
        )
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        # Platform does not provide a reliable process-liveness probe.
        return True

    return True


def _remove_stale_lock_if_safe(
    lock_path: Path,
) -> bool:
    try:
        stat_result = lock_path.stat()
    except FileNotFoundError:
        return True

    age = time.time() - stat_result.st_mtime

    if age < LIFECYCLE_STALE_LOCK_SECONDS:
        return False

    if _lock_owner_is_alive(lock_path):
        return False

    try:
        lock_path.unlink()
    except FileNotFoundError:
        pass

    return True


@contextmanager
def lifecycle_state_lock(
    path: Path | str,
    *,
    timeout_seconds: float = (LIFECYCLE_LOCK_TIMEOUT_SECONDS),
) -> Iterator[None]:
    state_path = Path(path)

    _secure_directory(state_path.parent)

    lock_path = _lock_path(state_path)

    deadline = time.monotonic() + timeout_seconds

    descriptor: int | None = None

    while descriptor is None:
        try:
            descriptor = os.open(
                lock_path,
                (os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                LIFECYCLE_STATE_FILE_MODE,
            )

        except FileExistsError:
            if _remove_stale_lock_if_safe(lock_path):
                continue

            if time.monotonic() >= deadline:
                raise LifecycleStateStorageError(
                    f"Timed out acquiring lifecycle-state lock for {state_path}."
                )

            time.sleep(LIFECYCLE_LOCK_POLL_SECONDS)

    try:
        payload = json.dumps(
            {
                "pid": os.getpid(),
                "created_at": (datetime.now(UTC).isoformat()),
            },
            sort_keys=True,
        ).encode("utf-8")

        os.write(
            descriptor,
            payload,
        )

        os.fsync(descriptor)

        os.close(descriptor)

        descriptor = None

        _secure_file(lock_path)

        yield

    finally:
        if descriptor is not None:
            os.close(descriptor)

        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def load_lifecycle_state(
    path: Path | str,
) -> LifecycleStateStore:
    state_path = Path(path)

    if not state_path.exists():
        return LifecycleStateStore()

    try:
        raw = state_path.read_text(encoding="utf-8")

        data = json.loads(raw)

        return LifecycleStateStore.model_validate(data)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise LifecycleStateStorageError(
            f"Lifecycle-state file is unreadable, malformed, or unsupported: {state_path}."
        ) from exc


def _save_lifecycle_state_unlocked(
    path: Path | str,
    state: LifecycleStateStore,
) -> None:
    state_path = Path(path)

    _secure_directory(state_path.parent)

    temporary = _temporary_path(state_path)

    payload = (
        json.dumps(
            state.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    descriptor: int | None = None

    try:
        descriptor = os.open(
            temporary,
            (os.O_WRONLY | os.O_CREAT | os.O_TRUNC),
            LIFECYCLE_STATE_FILE_MODE,
        )

        with os.fdopen(
            descriptor,
            "wb",
            closefd=True,
        ) as handle:
            descriptor = None

            handle.write(payload)

            handle.flush()

            os.fsync(handle.fileno())

        _secure_file(temporary)

        os.replace(
            temporary,
            state_path,
        )

        _secure_file(state_path)

        _directory_fsync(state_path.parent)

    except OSError as exc:
        raise LifecycleStateStorageError(
            f"Failed to durably write lifecycle-state file {state_path}."
        ) from exc

    finally:
        if descriptor is not None:
            os.close(descriptor)

        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def save_lifecycle_state(
    path: Path | str,
    state: LifecycleStateStore,
) -> None:
    with lifecycle_state_lock(path):
        _save_lifecycle_state_unlocked(
            path,
            state,
        )


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
    expected_state: LifecycleStateStore | None = None,
    now: datetime | None = None,
) -> None:
    if not lifecycle.activatable or lifecycle.generation is None or lifecycle.signer_id is None:
        raise ValueError("Only an activatable external lifecycle decision can be recorded.")

    with lifecycle_state_lock(path):
        current_state = load_lifecycle_state(path)

        if expected_state is not None and current_state.model_dump(
            mode="json"
        ) != expected_state.model_dump(mode="json"):
            raise LifecycleStateStorageError(
                "Lifecycle-state changed concurrently after evaluation; activation must be retried."
            )

        existing = current_state.records.get(policy.policy_id)

        if existing is not None:
            if lifecycle.generation < existing.generation:
                raise LifecycleStateStorageError(
                    "Refusing to persist a lifecycle generation "
                    "lower than the currently recorded generation."
                )

            if (
                lifecycle.generation == existing.generation
                and lifecycle.policy_sha256 != existing.policy_sha256
            ):
                raise LifecycleStateStorageError(
                    "Refusing to persist a different policy digest "
                    "for an already recorded lifecycle generation."
                )

        current_state.records[policy.policy_id] = LifecycleStateRecord(
            generation=(lifecycle.generation),
            policy_sha256=(lifecycle.policy_sha256),
            signer_id=(lifecycle.signer_id),
            accepted_at=(now or datetime.now(UTC)),
        )

        _save_lifecycle_state_unlocked(
            path,
            current_state,
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
