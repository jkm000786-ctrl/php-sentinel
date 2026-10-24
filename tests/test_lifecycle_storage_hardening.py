import json
import os
import time
from datetime import UTC, datetime

import pytest

from php_sentinel.intelligence.lifecycle import (
    LIFECYCLE_STALE_LOCK_SECONDS,
    LifecycleStateStorageError,
    _lock_path,
    lifecycle_state_lock,
    load_lifecycle_state,
    record_accepted_lifecycle,
    save_lifecycle_state,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_sha256,
)
from php_sentinel.models.intelligence_lifecycle import (
    IntelligenceLifecycleDecision,
    IntelligenceLifecycleState,
    LifecycleStateRecord,
    LifecycleStateStore,
)

NOW = datetime(
    2026,
    10,
    23,
    18,
    0,
    tzinfo=UTC,
)


def activatable_decision(
    *,
    generation: int,
    digest: str | None = None,
    signer_id: str = "storage-signer",
):
    policy = default_policy()

    return IntelligenceLifecycleDecision(
        state=IntelligenceLifecycleState.CURRENT,
        activatable=True,
        policy_id=policy.policy_id,
        policy_sha256=(digest or policy_sha256(policy)),
        generation=generation,
        signer_id=signer_id,
        rationale=["test lifecycle decision"],
    )


def test_unknown_state_store_version_fails_closed(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"

    state_path.write_text(
        json.dumps(
            {
                "store_version": 999,
                "records": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="malformed, or unsupported",
    ):
        load_lifecycle_state(state_path)


def test_malformed_json_fails_closed(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"

    state_path.write_text(
        "{not-valid-json",
        encoding="utf-8",
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="malformed",
    ):
        load_lifecycle_state(state_path)


def test_state_write_is_atomic_and_temp_is_removed(
    tmp_path,
):
    state_path = tmp_path / "state" / "lifecycle.json"

    state = LifecycleStateStore()

    save_lifecycle_state(
        state_path,
        state,
    )

    assert state_path.exists()

    assert not state_path.with_suffix(".json.tmp").exists()

    loaded = load_lifecycle_state(state_path)

    assert loaded == state


@pytest.mark.skipif(
    os.name != "posix",
    reason=("POSIX permission semantics are not portable to Windows."),
)
def test_state_permissions_are_restricted(
    tmp_path,
):
    state_path = tmp_path / "secure" / "lifecycle.json"

    save_lifecycle_state(
        state_path,
        LifecycleStateStore(),
    )

    directory_mode = state_path.parent.stat().st_mode & 0o777

    file_mode = state_path.stat().st_mode & 0o777

    assert directory_mode == 0o700
    assert file_mode == 0o600


def test_live_lock_causes_bounded_failure(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"

    with (
        lifecycle_state_lock(state_path),
        pytest.raises(
            LifecycleStateStorageError,
            match="Timed out acquiring",
        ),
        lifecycle_state_lock(
            state_path,
            timeout_seconds=0.05,
        ),
    ):
        pass


def test_stale_dead_owner_lock_is_recovered(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"

    lock_path = _lock_path(state_path)

    lock_path.write_text(
        json.dumps(
            {
                "pid": 99999999,
                "created_at": (NOW.isoformat()),
            }
        ),
        encoding="utf-8",
    )

    stale_time = time.time() - LIFECYCLE_STALE_LOCK_SECONDS - 5

    os.utime(
        lock_path,
        (
            stale_time,
            stale_time,
        ),
    )

    save_lifecycle_state(
        state_path,
        LifecycleStateStore(),
    )

    assert state_path.exists()
    assert not lock_path.exists()


def test_concurrent_state_change_is_detected(
    tmp_path,
):
    policy = default_policy()

    state_path = tmp_path / "lifecycle.json"

    evaluated_state = LifecycleStateStore()

    save_lifecycle_state(
        state_path,
        evaluated_state,
    )

    changed_state = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=5,
                    policy_sha256=(policy_sha256(policy)),
                    signer_id=("storage-signer"),
                    accepted_at=NOW,
                )
            )
        }
    )

    save_lifecycle_state(
        state_path,
        changed_state,
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="changed concurrently",
    ):
        record_accepted_lifecycle(
            path=state_path,
            policy=policy,
            lifecycle=(activatable_decision(generation=6)),
            expected_state=(evaluated_state),
            now=NOW,
        )


def test_lower_generation_cannot_overwrite_state(
    tmp_path,
):
    policy = default_policy()

    state_path = tmp_path / "lifecycle.json"

    existing = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=7,
                    policy_sha256=(policy_sha256(policy)),
                    signer_id=("storage-signer"),
                    accepted_at=NOW,
                )
            )
        }
    )

    save_lifecycle_state(
        state_path,
        existing,
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="lower than",
    ):
        record_accepted_lifecycle(
            path=state_path,
            policy=policy,
            lifecycle=(activatable_decision(generation=6)),
            now=NOW,
        )

    persisted = load_lifecycle_state(state_path)

    assert persisted.records[policy.policy_id].generation == 7


def test_lifecycle_state_read_rejects_symlink(
    tmp_path,
):
    outside = tmp_path / "outside-state.json"
    outside.write_text(
        json.dumps(LifecycleStateStore().model_dump(mode="json")),
        encoding="utf-8",
    )

    state_path = tmp_path / "lifecycle.json"
    state_path.symlink_to(outside)

    with pytest.raises(
        LifecycleStateStorageError,
        match="symbolic link",
    ):
        load_lifecycle_state(state_path)


def test_lifecycle_state_read_rejects_non_regular_file(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"
    state_path.mkdir()

    with pytest.raises(
        LifecycleStateStorageError,
        match="not a regular file",
    ):
        load_lifecycle_state(state_path)


def test_lifecycle_state_write_rejects_symlinked_temporary_file(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")

    outside = tmp_path / "outside.json"
    outside.write_text(
        "do-not-modify",
        encoding="utf-8",
    )

    temporary.symlink_to(outside)

    with pytest.raises(
        LifecycleStateStorageError,
        match="durably write",
    ):
        save_lifecycle_state(
            state_path,
            LifecycleStateStore(),
        )

    assert outside.read_text(encoding="utf-8") == "do-not-modify"


def test_symlinked_lock_fails_closed(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"
    lock_path = _lock_path(state_path)

    outside = tmp_path / "outside.lock"
    outside.write_text(
        json.dumps(
            {
                "pid": 99999999,
                "created_at": NOW.isoformat(),
            }
        ),
        encoding="utf-8",
    )

    stale_time = time.time() - LIFECYCLE_STALE_LOCK_SECONDS - 5

    os.utime(
        outside,
        (
            stale_time,
            stale_time,
        ),
    )

    lock_path.symlink_to(outside)

    with pytest.raises(
        LifecycleStateStorageError,
        match="symbolic link",
    ):
        save_lifecycle_state(
            state_path,
            LifecycleStateStore(),
        )

    assert lock_path.is_symlink()
    assert outside.exists()


def test_non_regular_lock_fails_closed(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"
    lock_path = _lock_path(state_path)

    lock_path.mkdir()

    with pytest.raises(
        LifecycleStateStorageError,
        match="not a regular file",
    ):
        save_lifecycle_state(
            state_path,
            LifecycleStateStore(),
        )


def test_stale_lock_replacement_is_not_unlinked(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.lifecycle as lifecycle_module

    state_path = tmp_path / "lifecycle.json"
    lock_path = _lock_path(state_path)

    lock_path.write_text(
        json.dumps(
            {
                "pid": 99999999,
                "created_at": NOW.isoformat(),
            }
        ),
        encoding="utf-8",
    )

    stale_time = time.time() - LIFECYCLE_STALE_LOCK_SECONDS - 5

    os.utime(
        lock_path,
        (
            stale_time,
            stale_time,
        ),
    )

    real_relative_status = lifecycle_module._relative_status
    replaced = False

    def replace_before_identity_check(
        anchor,
        name,
    ):
        nonlocal replaced

        if name == lock_path.name and not replaced:
            replaced = True

            lock_path.unlink()

            lock_path.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "created_at": NOW.isoformat(),
                    }
                ),
                encoding="utf-8",
            )

        return real_relative_status(
            anchor,
            name,
        )

    monkeypatch.setattr(
        lifecycle_module,
        "_relative_status",
        replace_before_identity_check,
    )

    anchor = lifecycle_module._open_state_directory(
        state_path,
        create=False,
    )

    assert anchor is not None

    try:
        removed = lifecycle_module._remove_stale_lock_if_safe(
            anchor,
            lock_path.name,
        )
    finally:
        lifecycle_module._close_state_directory(anchor)

    assert removed is False
    assert lock_path.exists()

    payload = json.loads(lock_path.read_text(encoding="utf-8"))

    assert payload["pid"] == os.getpid()


def test_lock_cleanup_does_not_unlink_replacement(
    tmp_path,
):
    state_path = tmp_path / "lifecycle.json"
    lock_path = _lock_path(state_path)

    with lifecycle_state_lock(state_path):
        lock_path.unlink()

        lock_path.write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "created_at": NOW.isoformat(),
                }
            ),
            encoding="utf-8",
        )

    assert lock_path.exists()

    payload = json.loads(lock_path.read_text(encoding="utf-8"))

    assert payload["pid"] == os.getpid()

    lock_path.unlink()


def test_lock_and_state_write_remain_bound_to_open_directory(
    tmp_path,
):
    import php_sentinel.intelligence.lifecycle as lifecycle_module

    state_directory = tmp_path / "state"
    state_path = state_directory / "lifecycle.json"

    replacement_payload = "replacement-directory-state"

    with lifecycle_state_lock(state_path) as anchor:
        displaced_directory = tmp_path / "state-original"

        state_directory.rename(displaced_directory)
        state_directory.mkdir()

        replacement_state = state_directory / "lifecycle.json"
        replacement_state.write_text(
            replacement_payload,
            encoding="utf-8",
        )

        lifecycle_module._save_lifecycle_state_unlocked(
            state_path,
            LifecycleStateStore(),
            _anchor=anchor,
        )

    persisted_original = displaced_directory / "lifecycle.json"

    assert persisted_original.exists()
    assert replacement_state.read_text(encoding="utf-8") == replacement_payload

    loaded = load_lifecycle_state(persisted_original)

    assert loaded == LifecycleStateStore()
