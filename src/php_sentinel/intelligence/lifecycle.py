from __future__ import annotations

import errno
import json
import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from php_sentinel.intelligence.delegation import (
    signer_delegation_revocation_sha256,
)
from php_sentinel.intelligence.repository import (
    policy_sha256,
)
from php_sentinel.models.intelligence_lifecycle import (
    DelegationHistoryRecord,
    DelegationRevocationHistoryRecord,
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


@dataclass(frozen=True)
class _StateDirectoryAnchor:
    directory_fd: int
    state_name: str
    state_path: Path


def _state_lock_name(
    state_name: str,
) -> str:
    state = Path(state_name)
    return state.with_suffix(state.suffix + ".lock").name


def _state_temporary_name(
    state_name: str,
) -> str:
    state = Path(state_name)
    return state.with_suffix(state.suffix + ".tmp").name


def _lock_path(
    state_path: Path,
) -> Path:
    return state_path.with_suffix(state_path.suffix + ".lock")


def _temporary_path(
    state_path: Path,
) -> Path:
    return state_path.with_suffix(state_path.suffix + ".tmp")


def _open_state_directory(
    state_path: Path,
    *,
    create: bool,
) -> _StateDirectoryAnchor | None:
    directory = state_path.parent

    if create:
        directory.mkdir(
            parents=True,
            exist_ok=True,
            mode=LIFECYCLE_STATE_DIRECTORY_MODE,
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    try:
        descriptor = os.open(
            directory,
            flags,
        )
    except FileNotFoundError:
        if not create:
            return None

        raise LifecycleStateStorageError(
            f"Lifecycle-state directory does not exist: {directory}."
        ) from None
    except OSError as exc:
        if exc.errno in (
            errno.ELOOP,
            errno.ENOTDIR,
        ):
            raise LifecycleStateStorageError(
                "Lifecycle-state directory must be a real directory "
                f"and must not be a symbolic link: {directory}."
            ) from exc

        raise LifecycleStateStorageError(
            f"Lifecycle-state directory could not be opened safely: {directory}."
        ) from exc

    try:
        status = os.fstat(descriptor)

        if not stat.S_ISDIR(status.st_mode):
            raise LifecycleStateStorageError(
                f"Lifecycle-state directory is not a directory: {directory}."
            )

        try:
            os.fchmod(
                descriptor,
                LIFECYCLE_STATE_DIRECTORY_MODE,
            )
        except OSError:
            # Some filesystems cannot enforce POSIX mode bits.
            pass

        return _StateDirectoryAnchor(
            directory_fd=descriptor,
            state_name=state_path.name,
            state_path=state_path,
        )

    except Exception:
        os.close(descriptor)
        raise


def _close_state_directory(
    anchor: _StateDirectoryAnchor,
) -> None:
    os.close(anchor.directory_fd)


def _directory_fsync_anchor(
    anchor: _StateDirectoryAnchor,
) -> None:
    try:
        os.fsync(anchor.directory_fd)
    except OSError:
        # Directory fsync is not available on every platform/filesystem.
        pass


def _read_descriptor_bytes(
    descriptor: int,
    *,
    chunk_size: int = 1024 * 1024,
) -> bytes:
    chunks: list[bytes] = []

    while True:
        chunk = os.read(
            descriptor,
            chunk_size,
        )

        if not chunk:
            break

        chunks.append(chunk)

    return b"".join(chunks)


def _same_file_identity(
    left: os.stat_result,
    right: os.stat_result,
) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _relative_status(
    anchor: _StateDirectoryAnchor,
    name: str,
) -> os.stat_result | None:
    try:
        return os.stat(
            name,
            dir_fd=anchor.directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None


def _unlink_relative_if_identity_matches(
    anchor: _StateDirectoryAnchor,
    name: str,
    expected_status: os.stat_result,
    *,
    description: str,
) -> bool:
    current_status = _relative_status(
        anchor,
        name,
    )

    if current_status is None:
        return True

    if not stat.S_ISREG(current_status.st_mode):
        raise LifecycleStateStorageError(
            f"{description} is not a regular file: {anchor.state_path.parent / name}."
        )

    if not _same_file_identity(
        expected_status,
        current_status,
    ):
        return False

    try:
        os.unlink(
            name,
            dir_fd=anchor.directory_fd,
        )
    except FileNotFoundError:
        return True

    return True


def _open_lock_snapshot(
    anchor: _StateDirectoryAnchor,
    lock_name: str,
) -> tuple[int, os.stat_result] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    lock_path = anchor.state_path.parent / lock_name

    try:
        descriptor = os.open(
            lock_name,
            flags,
            dir_fd=anchor.directory_fd,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise LifecycleStateStorageError(
                f"Lifecycle-state lock must not be a symbolic link: {lock_path}."
            ) from exc

        raise LifecycleStateStorageError(
            f"Lifecycle-state lock could not be opened safely: {lock_path}."
        ) from exc

    try:
        status = os.fstat(descriptor)

        if not stat.S_ISREG(status.st_mode):
            raise LifecycleStateStorageError(
                f"Lifecycle-state lock is not a regular file: {lock_path}."
            )

        return descriptor, status

    except Exception:
        os.close(descriptor)
        raise


def _read_lock_owner_pid(
    descriptor: int,
) -> int | None:
    try:
        os.lseek(
            descriptor,
            0,
            os.SEEK_SET,
        )

        data = json.loads(
            _read_descriptor_bytes(
                descriptor,
                chunk_size=64 * 1024,
            ).decode("utf-8")
        )

        pid = int(data["pid"])

    except (
        OSError,
        UnicodeDecodeError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None

    if pid <= 0:
        return None

    return pid


def _lock_owner_pid_is_alive(
    pid: int | None,
) -> bool:
    if pid is None:
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
    anchor: _StateDirectoryAnchor,
    lock_name: str,
) -> bool:
    snapshot = _open_lock_snapshot(
        anchor,
        lock_name,
    )

    if snapshot is None:
        return True

    descriptor, opened_status = snapshot

    try:
        age = time.time() - opened_status.st_mtime

        if age < LIFECYCLE_STALE_LOCK_SECONDS:
            return False

        owner_pid = _read_lock_owner_pid(descriptor)

        if _lock_owner_pid_is_alive(owner_pid):
            return False

        return _unlink_relative_if_identity_matches(
            anchor,
            lock_name,
            opened_status,
            description="Lifecycle-state lock",
        )

    finally:
        os.close(descriptor)


@contextmanager
def lifecycle_state_lock(
    path: Path | str,
    *,
    timeout_seconds: float = (LIFECYCLE_LOCK_TIMEOUT_SECONDS),
) -> Iterator[_StateDirectoryAnchor]:
    state_path = Path(path)

    anchor = _open_state_directory(
        state_path,
        create=True,
    )

    if anchor is None:
        raise LifecycleStateStorageError(
            f"Lifecycle-state directory could not be opened: {state_path.parent}."
        )

    lock_name = _state_lock_name(anchor.state_name)
    lock_path = state_path.parent / lock_name

    deadline = time.monotonic() + timeout_seconds

    descriptor: int | None = None
    acquired_status: os.stat_result | None = None

    try:
        while descriptor is None:
            try:
                lock_flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )

                descriptor = os.open(
                    lock_name,
                    lock_flags,
                    LIFECYCLE_STATE_FILE_MODE,
                    dir_fd=anchor.directory_fd,
                )

                acquired_status = os.fstat(descriptor)

                if not stat.S_ISREG(acquired_status.st_mode):
                    raise LifecycleStateStorageError(
                        f"Lifecycle-state lock is not a regular file: {lock_path}."
                    )

                try:
                    os.fchmod(
                        descriptor,
                        LIFECYCLE_STATE_FILE_MODE,
                    )
                except OSError:
                    pass

            except FileExistsError:
                if _remove_stale_lock_if_safe(
                    anchor,
                    lock_name,
                ):
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
                    "created_at": datetime.now(UTC).isoformat(),
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

            yield anchor

        finally:
            if descriptor is not None:
                os.close(descriptor)

            if acquired_status is not None:
                _unlink_relative_if_identity_matches(
                    anchor,
                    lock_name,
                    acquired_status,
                    description="Lifecycle-state lock",
                )

    finally:
        _close_state_directory(anchor)


def _read_lifecycle_state_bytes(
    state_path: Path,
    *,
    _anchor: _StateDirectoryAnchor | None = None,
) -> bytes | None:
    anchor = _anchor
    owns_anchor = False

    if anchor is None:
        anchor = _open_state_directory(
            state_path,
            create=False,
        )

        if anchor is None:
            return None

        owns_anchor = True

    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

        try:
            descriptor = os.open(
                anchor.state_name,
                flags,
                dir_fd=anchor.directory_fd,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise LifecycleStateStorageError(
                    f"Lifecycle-state file must not be a symbolic link: {state_path}."
                ) from exc

            raise LifecycleStateStorageError(
                f"Lifecycle-state file could not be opened safely: {state_path}."
            ) from exc

        try:
            status = os.fstat(descriptor)

            if not stat.S_ISREG(status.st_mode):
                raise LifecycleStateStorageError(
                    f"Lifecycle-state path is not a regular file: {state_path}."
                )

            return _read_descriptor_bytes(descriptor)

        finally:
            os.close(descriptor)

    finally:
        if owns_anchor:
            _close_state_directory(anchor)


def load_lifecycle_state(
    path: Path | str,
    *,
    _anchor: _StateDirectoryAnchor | None = None,
) -> LifecycleStateStore:
    state_path = Path(path)

    try:
        payload = _read_lifecycle_state_bytes(
            state_path,
            _anchor=_anchor,
        )

        if payload is None:
            return LifecycleStateStore()

        data = json.loads(payload.decode("utf-8"))

        return LifecycleStateStore.model_validate(data)

    except LifecycleStateStorageError:
        raise
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise LifecycleStateStorageError(
            f"Lifecycle-state file is unreadable, malformed, or unsupported: {state_path}."
        ) from exc


def _save_lifecycle_state_unlocked(
    path: Path | str,
    state: LifecycleStateStore,
    *,
    _anchor: _StateDirectoryAnchor | None = None,
) -> None:
    state_path = Path(path)

    anchor = _anchor
    owns_anchor = False

    if anchor is None:
        anchor = _open_state_directory(
            state_path,
            create=True,
        )

        if anchor is None:
            raise LifecycleStateStorageError(
                f"Lifecycle-state directory could not be opened: {state_path.parent}."
            )

        owns_anchor = True

    temporary_name = _state_temporary_name(anchor.state_name)
    temporary_path = state_path.parent / temporary_name

    payload = (
        json.dumps(
            state.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    descriptor: int | None = None
    temporary_status: os.stat_result | None = None

    try:
        temporary_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

        descriptor = os.open(
            temporary_name,
            temporary_flags,
            LIFECYCLE_STATE_FILE_MODE,
            dir_fd=anchor.directory_fd,
        )

        temporary_status = os.fstat(descriptor)

        if not stat.S_ISREG(temporary_status.st_mode):
            raise LifecycleStateStorageError(
                f"Lifecycle-state temporary object is not a regular file: {temporary_path}."
            )

        try:
            os.fchmod(
                descriptor,
                LIFECYCLE_STATE_FILE_MODE,
            )
        except OSError:
            pass

        with os.fdopen(
            descriptor,
            "wb",
            closefd=True,
        ) as handle:
            descriptor = None

            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.rename(
            temporary_name,
            anchor.state_name,
            src_dir_fd=anchor.directory_fd,
            dst_dir_fd=anchor.directory_fd,
        )

        temporary_status = None

        _directory_fsync_anchor(anchor)

    except OSError as exc:
        raise LifecycleStateStorageError(
            f"Failed to durably write lifecycle-state file {state_path}."
        ) from exc

    finally:
        if descriptor is not None:
            os.close(descriptor)

        if temporary_status is not None:
            _unlink_relative_if_identity_matches(
                anchor,
                temporary_name,
                temporary_status,
                description="Lifecycle-state temporary file",
            )

        if owns_anchor:
            _close_state_directory(anchor)


def save_lifecycle_state(
    path: Path | str,
    state: LifecycleStateStore,
) -> None:
    with lifecycle_state_lock(path) as anchor:
        _save_lifecycle_state_unlocked(
            path,
            state,
            _anchor=anchor,
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
            delegated_minimum = trust.authorized_predecessor_minimum_generations.get(
                record.signer_id
            )

            delegation_evidence = trust.authorized_predecessor_delegations.get(record.signer_id)

            delegation_key = f"intelligence|{record.signer_id}|{trust.signer_id}"

            historical_delegation = (
                state.delegation_records.get(delegation_key) if state is not None else None
            )

            delegation_history_valid = delegation_evidence is not None

            if delegation_evidence is not None and state is not None:
                revocation_key = (
                    f"intelligence|{record.signer_id}|{trust.signer_id}|"
                    f"{delegation_evidence.sequence}|"
                    f"{delegation_evidence.delegation_sha256}"
                )

                if revocation_key in state.revocation_records:
                    delegation_history_valid = False

            if delegation_evidence is not None and historical_delegation is not None:
                if delegation_evidence.sequence < historical_delegation.sequence:
                    delegation_history_valid = False

                if delegation_evidence.sequence == historical_delegation.sequence and (
                    delegation_evidence.delegation_sha256 != historical_delegation.delegation_sha256
                ):
                    delegation_history_valid = False

            rotation_authorized = (
                record.signer_id in trust.authorized_predecessor_signer_ids
                and delegated_minimum is not None
                and delegation_history_valid
                and manifest.generation >= delegated_minimum
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

    rotation_predecessor = None
    rotation_sequence = None
    rotation_digest = None

    if record is not None and trust.signer_id != record.signer_id:
        selected = trust.authorized_predecessor_delegations.get(record.signer_id)

        if selected is not None:
            rotation_predecessor = record.signer_id
            rotation_sequence = selected.sequence
            rotation_digest = selected.delegation_sha256

    return IntelligenceLifecycleDecision(
        state=IntelligenceLifecycleState.CURRENT,
        activatable=True,
        **base,
        rotation_predecessor_signer_id=(rotation_predecessor),
        rotation_delegation_sequence=(rotation_sequence),
        rotation_delegation_sha256=(rotation_digest),
        rationale=[
            (
                "Manifest signature, freshness, expiry, "
                "generation, signer pin, and rollback "
                "checks passed."
            )
        ],
    )


def record_observed_delegation_revocations(
    *,
    path: Path | str,
    revocations,
    expected_state: LifecycleStateStore | None = None,
    now: datetime | None = None,
) -> LifecycleStateStore:
    observed_at = now or datetime.now(UTC)

    with lifecycle_state_lock(path) as anchor:
        current_state = load_lifecycle_state(path, _anchor=anchor)

        if expected_state is not None and current_state.model_dump(
            mode="json"
        ) != expected_state.model_dump(mode="json"):
            raise LifecycleStateStorageError(
                "Lifecycle-state changed concurrently before revocation "
                "observation commit; activation must be retried."
            )

        updated = current_state.model_copy(deep=True)

        for revocation in revocations:
            key = (
                f"{revocation.context}|"
                f"{revocation.predecessor_signer_id}|"
                f"{revocation.successor_signer_id}|"
                f"{revocation.delegation_sequence}|"
                f"{revocation.delegation_sha256}"
            )

            digest = signer_delegation_revocation_sha256(revocation)
            historical = updated.revocation_records.get(key)

            if historical is not None:
                if revocation.revocation_sequence < historical.revocation_sequence:
                    raise LifecycleStateStorageError(
                        "Refusing to persist an older delegation revocation sequence."
                    )

                if (
                    revocation.revocation_sequence == historical.revocation_sequence
                    and digest != historical.revocation_sha256
                ):
                    raise LifecycleStateStorageError(
                        "Refusing same-sequence delegation revocation digest replacement."
                    )

            updated.revocation_records[key] = DelegationRevocationHistoryRecord(
                delegation_sequence=revocation.delegation_sequence,
                delegation_sha256=revocation.delegation_sha256,
                revocation_sequence=revocation.revocation_sequence,
                revocation_sha256=digest,
                observed_at=observed_at,
            )

        _save_lifecycle_state_unlocked(
            path,
            updated,
            _anchor=anchor,
        )

        return updated


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

    with lifecycle_state_lock(path) as anchor:
        current_state = load_lifecycle_state(path, _anchor=anchor)

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

        accepted_at = now or datetime.now(UTC)

        if (
            lifecycle.rotation_predecessor_signer_id is not None
            and lifecycle.rotation_delegation_sequence is not None
            and lifecycle.rotation_delegation_sha256 is not None
        ):
            delegation_key = (
                f"intelligence|{lifecycle.rotation_predecessor_signer_id}|{lifecycle.signer_id}"
            )

            historical = current_state.delegation_records.get(delegation_key)

            if historical is not None:
                if lifecycle.rotation_delegation_sequence < historical.sequence:
                    raise LifecycleStateStorageError(
                        "Refusing to persist an older delegation sequence."
                    )

                if lifecycle.rotation_delegation_sequence == historical.sequence and (
                    lifecycle.rotation_delegation_sha256 != historical.delegation_sha256
                ):
                    raise LifecycleStateStorageError(
                        "Refusing same-sequence delegation digest replacement."
                    )

            current_state.delegation_records[delegation_key] = DelegationHistoryRecord(
                sequence=(lifecycle.rotation_delegation_sequence),
                delegation_sha256=(lifecycle.rotation_delegation_sha256),
                accepted_at=accepted_at,
            )

        current_state.records[policy.policy_id] = LifecycleStateRecord(
            generation=(lifecycle.generation),
            policy_sha256=(lifecycle.policy_sha256),
            signer_id=(lifecycle.signer_id),
            accepted_at=accepted_at,
        )

        _save_lifecycle_state_unlocked(
            path,
            current_state,
            _anchor=anchor,
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
