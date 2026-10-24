from __future__ import annotations

import pytest

from php_sentinel.intelligence.format_governance import (
    AUTHORITY_FORMAT_MIGRATIONS,
    AUTHORITY_FORMAT_POLICIES,
    AuthorityFormatKind,
    AuthorityFormatPolicy,
    FormatVersionDisposition,
    authority_format_migration_supported,
    evaluate_authority_format_version,
    require_current_writable_format,
)
from php_sentinel.models.intelligence_lifecycle import (
    SUPPORTED_LIFECYCLE_STATE_STORE_VERSIONS,
)
from php_sentinel.models.registry_trust import (
    SUPPORTED_REGISTRY_STATE_VERSIONS,
)
from php_sentinel.models.state_auth import (
    SUPPORTED_AUTHORITY_STATE_AUTH_VERSIONS,
)
from php_sentinel.models.state_key import (
    SUPPORTED_AUTHORITY_STATE_KEY_FILE_VERSIONS,
)

EXPECTED_SUPPORTED = {
    AuthorityFormatKind.LIFECYCLE_STATE_STORE: SUPPORTED_LIFECYCLE_STATE_STORE_VERSIONS,
    AuthorityFormatKind.REGISTRY_STATE_STORE: SUPPORTED_REGISTRY_STATE_VERSIONS,
    AuthorityFormatKind.AUTHORITY_STATE_ENVELOPE: SUPPORTED_AUTHORITY_STATE_AUTH_VERSIONS,
    AuthorityFormatKind.AUTHORITY_KEY_FILE: SUPPORTED_AUTHORITY_STATE_KEY_FILE_VERSIONS,
}


@pytest.mark.parametrize(
    ("kind", "supported"),
    EXPECTED_SUPPORTED.items(),
)
def test_governance_policy_matches_model_supported_versions(
    kind,
    supported,
):
    policy = AUTHORITY_FORMAT_POLICIES[kind]

    assert policy.supported_versions == supported
    assert policy.current_write_version == max(supported)


@pytest.mark.parametrize(
    "kind",
    list(AuthorityFormatKind),
)
def test_current_authority_versions_are_readable_and_writable(
    kind,
):
    current = AUTHORITY_FORMAT_POLICIES[kind].current_write_version

    decision = evaluate_authority_format_version(
        kind,
        current,
    )

    assert decision.disposition is FormatVersionDisposition.CURRENT
    assert decision.readable is True
    assert decision.writable is True
    assert decision.migration_required is False
    assert decision.migration_supported is False


@pytest.mark.parametrize(
    "kind",
    list(AuthorityFormatKind),
)
def test_future_authority_versions_fail_closed(
    kind,
):
    current = AUTHORITY_FORMAT_POLICIES[kind].current_write_version

    decision = evaluate_authority_format_version(
        kind,
        current + 1,
    )

    assert decision.disposition is FormatVersionDisposition.FUTURE_UNSUPPORTED
    assert decision.readable is False
    assert decision.writable is False
    assert decision.migration_supported is False


@pytest.mark.parametrize(
    "version",
    [
        None,
        0,
        -1,
        True,
        False,
        1.0,
        "1",
    ],
)
def test_invalid_version_values_fail_closed(
    version,
):
    decision = evaluate_authority_format_version(
        AuthorityFormatKind.LIFECYCLE_STATE_STORE,
        version,
    )

    assert decision.disposition is FormatVersionDisposition.INVALID
    assert decision.readable is False
    assert decision.writable is False
    assert decision.observed_version is None


def test_older_supported_format_is_read_only_until_explicit_migration():
    policy = AuthorityFormatPolicy(
        kind=AuthorityFormatKind.LIFECYCLE_STATE_STORE,
        supported_versions=frozenset({1, 2}),
        current_write_version=2,
    )

    assert policy.supported_versions == frozenset({1, 2})
    assert policy.current_write_version == 2

    # The production policy currently has only v1. This assertion records the
    # governance rule for the day a compatibility-readable older version exists:
    # readable does not imply writable.
    assert 1 in policy.supported_versions
    assert 1 != policy.current_write_version


def test_policy_rejects_current_version_outside_supported_set():
    with pytest.raises(
        ValueError,
        match="current write version must also be readable",
    ):
        AuthorityFormatPolicy(
            kind=AuthorityFormatKind.AUTHORITY_KEY_FILE,
            supported_versions=frozenset({1}),
            current_write_version=2,
        )


def test_policy_rejects_non_highest_current_write_version():
    with pytest.raises(
        ValueError,
        match="highest supported version",
    ):
        AuthorityFormatPolicy(
            kind=AuthorityFormatKind.AUTHORITY_STATE_ENVELOPE,
            supported_versions=frozenset({1, 2}),
            current_write_version=1,
        )


@pytest.mark.parametrize(
    "supported",
    [
        frozenset(),
        frozenset({0}),
        frozenset({-1, 1}),
        frozenset({True}),
    ],
)
def test_policy_rejects_invalid_supported_version_sets(
    supported,
):
    with pytest.raises(ValueError):
        AuthorityFormatPolicy(
            kind=AuthorityFormatKind.REGISTRY_STATE_STORE,
            supported_versions=supported,
            current_write_version=1,
        )


def test_no_implicit_authority_format_migrations_are_registered():
    assert AUTHORITY_FORMAT_MIGRATIONS == frozenset()

    for kind in AuthorityFormatKind:
        assert (
            authority_format_migration_supported(
                kind,
                from_version=1,
                to_version=2,
            )
            is False
        )


@pytest.mark.parametrize(
    "kind",
    list(AuthorityFormatKind),
)
def test_require_current_writable_format_accepts_current(kind):
    current = AUTHORITY_FORMAT_POLICIES[kind].current_write_version

    decision = require_current_writable_format(
        kind,
        current,
    )

    assert decision.writable is True


@pytest.mark.parametrize(
    "kind",
    list(AuthorityFormatKind),
)
def test_require_current_writable_format_rejects_future_version(kind):
    current = AUTHORITY_FORMAT_POLICIES[kind].current_write_version

    with pytest.raises(
        ValueError,
        match="is not writable",
    ):
        require_current_writable_format(
            kind,
            current + 1,
        )


def test_unsigned_to_authenticated_migration_is_not_misrepresented_as_store_version_migration():
    assert AUTHORITY_FORMAT_MIGRATIONS == frozenset()


def test_lifecycle_save_rejects_noncurrent_store_version_before_write(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.lifecycle as lifecycle_module
    from php_sentinel.intelligence.lifecycle import (
        LifecycleStateStorageError,
        save_lifecycle_state,
    )
    from php_sentinel.models.intelligence_lifecycle import LifecycleStateStore

    path = tmp_path / "lifecycle.json"
    state = LifecycleStateStore()

    original = lifecycle_module.require_current_writable_format

    def reject_current(kind, version):
        if kind is AuthorityFormatKind.LIFECYCLE_STATE_STORE:
            raise ValueError("test noncurrent format")
        return original(kind, version)

    monkeypatch.setattr(
        lifecycle_module,
        "require_current_writable_format",
        reject_current,
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="current writable store format",
    ):
        save_lifecycle_state(
            path,
            state,
        )

    assert not path.exists()


def test_registry_save_rejects_noncurrent_store_version_before_write(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.registry_trust as registry_module
    from php_sentinel.intelligence.registry_trust import (
        SourceRegistryStateStorageError,
        save_source_registry_state,
    )
    from php_sentinel.models.registry_trust import SourceRegistryStateStore

    path = tmp_path / "registry.json"
    state = SourceRegistryStateStore()

    original = registry_module.require_current_writable_format

    def reject_current(kind, version):
        if kind is AuthorityFormatKind.REGISTRY_STATE_STORE:
            raise ValueError("test noncurrent format")
        return original(kind, version)

    monkeypatch.setattr(
        registry_module,
        "require_current_writable_format",
        reject_current,
    )

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="current writable store format",
    ):
        save_source_registry_state(
            path,
            state,
        )

    assert not path.exists()


def test_envelope_creation_requires_current_auth_format(
    monkeypatch,
):
    import php_sentinel.intelligence.state_auth as state_auth_module
    from php_sentinel.intelligence.state_auth import create_authority_state_envelope
    from php_sentinel.models.intelligence_lifecycle import LifecycleStateStore

    original = state_auth_module.require_current_writable_format

    def reject_current(kind, version):
        if kind is AuthorityFormatKind.AUTHORITY_STATE_ENVELOPE:
            raise ValueError("test noncurrent format")
        return original(kind, version)

    monkeypatch.setattr(
        state_auth_module,
        "require_current_writable_format",
        reject_current,
    )

    with pytest.raises(
        ValueError,
        match="test noncurrent format",
    ):
        create_authority_state_envelope(
            context="lifecycle",
            key_id="test-authority",
            key=b"k" * 32,
            state=LifecycleStateStore(),
        )


def test_key_generation_requires_current_key_file_format_before_creation(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.state_key as state_key_module
    from php_sentinel.intelligence.state_key import (
        AuthorityStateKeyStorageError,
        generate_authority_state_key,
    )

    path = tmp_path / "authority-state.key.json"
    original = state_key_module.require_current_writable_format

    def reject_current(kind, version):
        if kind is AuthorityFormatKind.AUTHORITY_KEY_FILE:
            raise ValueError("test noncurrent format")
        return original(kind, version)

    monkeypatch.setattr(
        state_key_module,
        "require_current_writable_format",
        reject_current,
    )

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="current writable key-file format",
    ):
        generate_authority_state_key(path)

    assert not path.exists()


def test_legacy_unsigned_to_authenticated_migration_still_uses_current_formats(
    tmp_path,
):
    from php_sentinel.intelligence.lifecycle import (
        load_lifecycle_state,
        migrate_lifecycle_state_to_authenticated,
        save_lifecycle_state,
    )
    from php_sentinel.intelligence.state_key import generate_authority_state_key
    from php_sentinel.models.intelligence_lifecycle import LifecycleStateStore

    state_path = tmp_path / "lifecycle.json"
    key_path = tmp_path / "authority-state.key.json"

    save_lifecycle_state(
        state_path,
        LifecycleStateStore(),
    )
    key = generate_authority_state_key(key_path)

    migrated = migrate_lifecycle_state_to_authenticated(
        state_path,
        authority_key=key,
    )

    assert migrated.store_version == 1

    loaded = load_lifecycle_state(
        state_path,
        authority_key=key,
        require_authenticated=True,
    )

    assert loaded == migrated


def test_future_lifecycle_store_version_is_rejected_by_loader(
    tmp_path,
):
    import json

    from php_sentinel.intelligence.lifecycle import (
        LifecycleStateStorageError,
        load_lifecycle_state,
    )

    path = tmp_path / "lifecycle.json"
    path.write_text(
        json.dumps(
            {
                "store_version": 2,
                "records": {},
                "delegation_records": {},
                "revocation_records": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="malformed|unsupported",
    ):
        load_lifecycle_state(path)


def test_future_registry_store_version_is_rejected_by_loader(
    tmp_path,
):
    import json

    from php_sentinel.intelligence.registry_trust import (
        SourceRegistryStateStorageError,
        load_source_registry_state,
    )

    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "store_version": 2,
                "records": {},
                "delegation_records": {},
                "revocation_records": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="malformed|unsupported",
    ):
        load_source_registry_state(path)


def test_future_authority_envelope_version_is_rejected_before_authentication(
    tmp_path,
):
    import base64
    import json

    from php_sentinel.intelligence.lifecycle import (
        LifecycleStateStorageError,
        load_lifecycle_state,
    )
    from php_sentinel.intelligence.state_key import generate_authority_state_key

    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "lifecycle.json"

    path.write_text(
        json.dumps(
            {
                "auth_version": 2,
                "context": "lifecycle",
                "algorithm": "hmac-sha256",
                "key_id": key.key_id,
                "state": {
                    "store_version": 1,
                    "records": {},
                    "delegation_records": {},
                    "revocation_records": {},
                },
                "mac_b64": base64.b64encode(b"x" * 32).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="authenticated authority-state envelope|malformed|unsupported",
    ):
        load_lifecycle_state(
            path,
            authority_key=key,
            require_authenticated=True,
        )


def test_future_key_file_version_is_rejected_by_loader(
    tmp_path,
):
    import base64
    import json

    from php_sentinel.intelligence.state_key import (
        AuthorityStateKeyStorageError,
        load_authority_state_key,
    )

    path = tmp_path / "authority-state.key.json"
    path.write_text(
        json.dumps(
            {
                "key_file_version": 2,
                "key_id": "future-key",
                "algorithm": "hmac-sha256",
                "key_b64": base64.b64encode(b"k" * 32).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="malformed or unsupported",
    ):
        load_authority_state_key(path)


def test_recovery_classifies_future_lifecycle_store_as_malformed_unsupported(
    tmp_path,
):
    import json

    from php_sentinel.intelligence.state_recovery import (
        AuthorityStateRecoveryStatus,
        diagnose_lifecycle_state,
    )

    path = tmp_path / "lifecycle.json"
    path.write_text(
        json.dumps(
            {
                "store_version": 2,
                "records": {},
                "delegation_records": {},
                "revocation_records": {},
            }
        ),
        encoding="utf-8",
    )

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.MALFORMED_OR_UNSUPPORTED
    assert diagnostic.recoverable_automatically is False


def test_recovery_classifies_future_key_file_as_malformed_unsupported(
    tmp_path,
):
    import base64
    import json

    from php_sentinel.intelligence.state_recovery import (
        AuthorityKeyRecoveryStatus,
        diagnose_authority_state_key,
    )

    path = tmp_path / "authority-state.key.json"
    path.write_text(
        json.dumps(
            {
                "key_file_version": 2,
                "key_id": "future-key",
                "algorithm": "hmac-sha256",
                "key_b64": base64.b64encode(b"k" * 32).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )

    diagnostic = diagnose_authority_state_key(path)

    assert diagnostic.status is AuthorityKeyRecoveryStatus.MALFORMED_OR_UNSUPPORTED
    assert diagnostic.recoverable_automatically is False
