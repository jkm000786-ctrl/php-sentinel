from __future__ import annotations

import json

import pytest

from php_sentinel.intelligence.lifecycle import (
    LifecycleStateStorageError,
    load_lifecycle_state,
    migrate_lifecycle_state_to_authenticated,
    save_lifecycle_state,
)
from php_sentinel.intelligence.registry_trust import (
    SourceRegistryStateStorageError,
    load_source_registry_state,
    migrate_source_registry_state_to_authenticated,
    save_source_registry_state,
)
from php_sentinel.intelligence.state_key import (
    generate_authority_state_key,
)
from php_sentinel.models.intelligence_lifecycle import LifecycleStateStore
from php_sentinel.models.registry_trust import SourceRegistryStateStore


def _key(tmp_path):
    return generate_authority_state_key(
        tmp_path / "authority-state.key.json",
        key_id="test-authority-v1",
    )


def test_authenticated_lifecycle_state_round_trip(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "lifecycle.json"
    state = LifecycleStateStore()

    save_lifecycle_state(
        path,
        state,
        authority_key=key,
    )

    loaded = load_lifecycle_state(
        path,
        authority_key=key,
        require_authenticated=True,
    )

    assert loaded == state

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["context"] == "lifecycle"
    assert raw["key_id"] == key.key_id
    assert "mac_b64" in raw
    assert "state" in raw


def test_authenticated_registry_state_round_trip(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "registry.json"
    state = SourceRegistryStateStore()

    save_source_registry_state(
        path,
        state,
        authority_key=key,
    )

    loaded = load_source_registry_state(
        path,
        authority_key=key,
        require_authenticated=True,
    )

    assert loaded == state

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["context"] == "registry"


def test_lifecycle_state_tampering_fails_closed(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
        authority_key=key,
    )

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["state"]["store_version"] = 999
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(
        LifecycleStateStorageError,
        match="authentication failed",
    ):
        load_lifecycle_state(
            path,
            authority_key=key,
            require_authenticated=True,
        )


def test_registry_state_tampering_fails_closed(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
        authority_key=key,
    )

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["state"]["store_version"] = 999
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="authentication failed",
    ):
        load_source_registry_state(
            path,
            authority_key=key,
            require_authenticated=True,
        )


def test_unsigned_lifecycle_state_rejected_when_required(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="not an authenticated",
    ):
        load_lifecycle_state(
            path,
            authority_key=key,
            require_authenticated=True,
        )


def test_unsigned_registry_state_rejected_when_required(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
    )

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="not an authenticated",
    ):
        load_source_registry_state(
            path,
            authority_key=key,
            require_authenticated=True,
        )


def test_legacy_lifecycle_state_remains_loadable_without_key(tmp_path):
    path = tmp_path / "lifecycle.json"
    state = LifecycleStateStore()

    save_lifecycle_state(path, state)

    assert load_lifecycle_state(path) == state


def test_legacy_registry_state_remains_loadable_without_key(tmp_path):
    path = tmp_path / "registry.json"
    state = SourceRegistryStateStore()

    save_source_registry_state(path, state)

    assert load_source_registry_state(path) == state


def test_authenticated_state_wrong_key_fails_closed(tmp_path):
    key1 = generate_authority_state_key(
        tmp_path / "key1.json",
        key_id="authority-one",
    )
    key2 = generate_authority_state_key(
        tmp_path / "key2.json",
        key_id="authority-two",
    )

    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
        authority_key=key1,
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="authentication failed",
    ):
        load_lifecycle_state(
            path,
            authority_key=key2,
            require_authenticated=True,
        )


def test_context_swap_is_rejected(tmp_path):
    key = _key(tmp_path)

    lifecycle_path = tmp_path / "lifecycle.json"
    registry_path = tmp_path / "registry.json"

    save_lifecycle_state(
        lifecycle_path,
        LifecycleStateStore(),
        authority_key=key,
    )

    registry_path.write_bytes(lifecycle_path.read_bytes())

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="authentication failed",
    ):
        load_source_registry_state(
            registry_path,
            authority_key=key,
            require_authenticated=True,
        )


def test_authenticated_lifecycle_state_cannot_be_loaded_as_legacy(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
        authority_key=key,
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="authenticated but no local authority-state key",
    ):
        load_lifecycle_state(path)


def test_authenticated_registry_state_cannot_be_loaded_as_legacy(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
        authority_key=key,
    )

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="authenticated but no local authority-state key",
    ):
        load_source_registry_state(path)


def test_explicit_lifecycle_legacy_migration(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "lifecycle.json"
    state = LifecycleStateStore()

    save_lifecycle_state(
        path,
        state,
    )

    migrated = migrate_lifecycle_state_to_authenticated(
        path,
        authority_key=key,
    )

    assert migrated == state

    loaded = load_lifecycle_state(
        path,
        authority_key=key,
        require_authenticated=True,
    )

    assert loaded == state

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["context"] == "lifecycle"
    assert raw["key_id"] == key.key_id


def test_explicit_registry_legacy_migration(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "registry.json"
    state = SourceRegistryStateStore()

    save_source_registry_state(
        path,
        state,
    )

    migrated = migrate_source_registry_state_to_authenticated(
        path,
        authority_key=key,
    )

    assert migrated == state

    loaded = load_source_registry_state(
        path,
        authority_key=key,
        require_authenticated=True,
    )

    assert loaded == state

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["context"] == "registry"
    assert raw["key_id"] == key.key_id


def test_lifecycle_migration_rejects_already_authenticated_state(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
        authority_key=key,
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="already uses an authenticated",
    ):
        migrate_lifecycle_state_to_authenticated(
            path,
            authority_key=key,
        )


def test_registry_migration_rejects_already_authenticated_state(tmp_path):
    key = _key(tmp_path)
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
        authority_key=key,
    )

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="already uses an authenticated",
    ):
        migrate_source_registry_state_to_authenticated(
            path,
            authority_key=key,
        )


def test_lifecycle_migration_requires_existing_legacy_state(tmp_path):
    key = _key(tmp_path)

    with pytest.raises(
        LifecycleStateStorageError,
        match="No legacy lifecycle-state file exists",
    ):
        migrate_lifecycle_state_to_authenticated(
            tmp_path / "missing-lifecycle.json",
            authority_key=key,
        )


def test_registry_migration_requires_existing_legacy_state(tmp_path):
    key = _key(tmp_path)

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="No legacy source-registry state file exists",
    ):
        migrate_source_registry_state_to_authenticated(
            tmp_path / "missing-registry.json",
            authority_key=key,
        )


def test_key_replacement_does_not_silently_rotate_authenticated_state(tmp_path):
    first_key = generate_authority_state_key(
        tmp_path / "first-key.json",
        key_id="authority-v1",
    )
    replacement_key = generate_authority_state_key(
        tmp_path / "replacement-key.json",
        key_id="authority-v2",
    )

    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
        authority_key=first_key,
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="authentication failed",
    ):
        load_lifecycle_state(
            path,
            authority_key=replacement_key,
            require_authenticated=True,
        )
