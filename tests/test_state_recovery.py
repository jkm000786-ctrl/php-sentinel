from __future__ import annotations

import json
from pathlib import Path

from php_sentinel.intelligence.lifecycle import save_lifecycle_state
from php_sentinel.intelligence.registry_trust import save_source_registry_state
from php_sentinel.intelligence.state_key import generate_authority_state_key
from php_sentinel.intelligence.state_recovery import (
    AuthorityKeyRecoveryStatus,
    AuthorityStateRecoveryStatus,
    diagnose_authority_state_key,
    diagnose_lifecycle_state,
    diagnose_source_registry_state,
)
from php_sentinel.models.intelligence_lifecycle import LifecycleStateStore
from php_sentinel.models.registry_trust import SourceRegistryStateStore


def test_missing_lifecycle_state_is_classified_without_creation(
    tmp_path,
):
    path = tmp_path / "missing-lifecycle.json"

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.MISSING
    assert diagnostic.authenticated is None
    assert diagnostic.recoverable_automatically is False
    assert not path.exists()


def test_missing_registry_state_is_classified_without_creation(
    tmp_path,
):
    path = tmp_path / "missing-registry.json"

    diagnostic = diagnose_source_registry_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.MISSING
    assert diagnostic.authenticated is None
    assert diagnostic.recoverable_automatically is False
    assert not path.exists()


def test_valid_legacy_lifecycle_state_is_classified(
    tmp_path,
):
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
    )

    before = path.read_bytes()

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_LEGACY
    assert diagnostic.authenticated is False
    assert path.read_bytes() == before


def test_valid_legacy_registry_state_is_classified(
    tmp_path,
):
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
    )

    before = path.read_bytes()

    diagnostic = diagnose_source_registry_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_LEGACY
    assert diagnostic.authenticated is False
    assert path.read_bytes() == before


def test_valid_authenticated_lifecycle_state_is_classified(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
        authority_key=key,
    )

    before = path.read_bytes()

    diagnostic = diagnose_lifecycle_state(
        path,
        authority_key=key,
    )

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_AUTHENTICATED
    assert diagnostic.authenticated is True
    assert path.read_bytes() == before


def test_valid_authenticated_registry_state_is_classified(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
        authority_key=key,
    )

    before = path.read_bytes()

    diagnostic = diagnose_source_registry_state(
        path,
        authority_key=key,
    )

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_AUTHENTICATED
    assert diagnostic.authenticated is True
    assert path.read_bytes() == before


def test_lifecycle_mac_tampering_is_classified_authentication_failed(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
        authority_key=key,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    data["state"]["store_version"] = 999
    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    before = path.read_bytes()

    diagnostic = diagnose_lifecycle_state(
        path,
        authority_key=key,
    )

    assert diagnostic.status is AuthorityStateRecoveryStatus.AUTHENTICATION_FAILED
    assert diagnostic.authenticated is True
    assert diagnostic.recoverable_automatically is False
    assert path.read_bytes() == before


def test_registry_mac_tampering_is_classified_authentication_failed(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
        authority_key=key,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    data["state"]["store_version"] = 999
    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    before = path.read_bytes()

    diagnostic = diagnose_source_registry_state(
        path,
        authority_key=key,
    )

    assert diagnostic.status is AuthorityStateRecoveryStatus.AUTHENTICATION_FAILED
    assert diagnostic.authenticated is True
    assert diagnostic.recoverable_automatically is False
    assert path.read_bytes() == before


def test_malformed_lifecycle_state_is_classified_without_rewrite(
    tmp_path,
):
    path = tmp_path / "lifecycle.json"
    original = b"{not-valid-json"
    path.write_bytes(original)

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.MALFORMED_OR_UNSUPPORTED
    assert diagnostic.recoverable_automatically is False
    assert path.read_bytes() == original


def test_malformed_registry_state_is_classified_without_rewrite(
    tmp_path,
):
    path = tmp_path / "registry.json"
    original = b"{not-valid-json"
    path.write_bytes(original)

    diagnostic = diagnose_source_registry_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.MALFORMED_OR_UNSUPPORTED
    assert diagnostic.recoverable_automatically is False
    assert path.read_bytes() == original


def test_symlinked_lifecycle_state_is_classified_unsafe_without_following(
    tmp_path,
):
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps(LifecycleStateStore().model_dump(mode="json")),
        encoding="utf-8",
    )

    path = tmp_path / "lifecycle.json"
    path.symlink_to(outside)

    outside_before = outside.read_bytes()

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.UNSAFE_STORAGE
    assert diagnostic.recoverable_automatically is False
    assert path.is_symlink()
    assert outside.read_bytes() == outside_before


def test_non_regular_registry_state_is_classified_unsafe(
    tmp_path,
):
    path = tmp_path / "registry.json"
    path.mkdir()

    diagnostic = diagnose_source_registry_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.UNSAFE_STORAGE
    assert diagnostic.recoverable_automatically is False
    assert path.is_dir()


def test_authenticated_lifecycle_without_key_is_classified_key_required(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
        authority_key=key,
    )

    before = path.read_bytes()

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.AUTHORITY_KEY_REQUIRED
    assert diagnostic.authenticated is True
    assert diagnostic.recoverable_automatically is False
    assert path.read_bytes() == before


def test_authenticated_registry_without_key_is_classified_key_required(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
        authority_key=key,
    )

    before = path.read_bytes()

    diagnostic = diagnose_source_registry_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.AUTHORITY_KEY_REQUIRED
    assert diagnostic.authenticated is True
    assert diagnostic.recoverable_automatically is False
    assert path.read_bytes() == before


def test_lifecycle_diagnostic_does_not_use_path_read_bytes(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
    )

    def forbidden_read_bytes(self):
        raise AssertionError(
            f"path-based read_bytes must not be used by recovery diagnostics: {self}"
        )

    monkeypatch.setattr(
        Path,
        "read_bytes",
        forbidden_read_bytes,
    )

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_LEGACY


def test_registry_diagnostic_does_not_use_path_read_bytes(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
    )

    def forbidden_read_bytes(self):
        raise AssertionError(
            f"path-based read_bytes must not be used by recovery diagnostics: {self}"
        )

    monkeypatch.setattr(
        Path,
        "read_bytes",
        forbidden_read_bytes,
    )

    diagnostic = diagnose_source_registry_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_LEGACY


def test_broken_symlink_lifecycle_state_is_unsafe_not_missing(
    tmp_path,
):
    path = tmp_path / "lifecycle.json"
    path.symlink_to(tmp_path / "missing-target.json")

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.UNSAFE_STORAGE
    assert diagnostic.recoverable_automatically is False
    assert path.is_symlink()


def test_broken_symlink_registry_state_is_unsafe_not_missing(
    tmp_path,
):
    path = tmp_path / "registry.json"
    path.symlink_to(tmp_path / "missing-target.json")

    diagnostic = diagnose_source_registry_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.UNSAFE_STORAGE
    assert diagnostic.recoverable_automatically is False
    assert path.is_symlink()


def test_missing_authority_key_is_classified_without_creation(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    diagnostic = diagnose_authority_state_key(path)

    assert diagnostic.status is AuthorityKeyRecoveryStatus.MISSING
    assert diagnostic.key_id is None
    assert diagnostic.recoverable_automatically is False
    assert not path.exists()


def test_valid_authority_key_is_classified_without_mutation(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    created = generate_authority_state_key(
        path,
        key_id="diagnostic-authority",
    )
    before = path.read_bytes()

    diagnostic = diagnose_authority_state_key(path)

    assert diagnostic.status is AuthorityKeyRecoveryStatus.VALID
    assert diagnostic.key_id == created.key_id
    assert diagnostic.recoverable_automatically is False
    assert path.read_bytes() == before


def test_malformed_authority_key_is_classified_without_replacement(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"
    original = b"{not-valid-json"
    path.write_bytes(original)

    diagnostic = diagnose_authority_state_key(path)

    assert diagnostic.status is AuthorityKeyRecoveryStatus.MALFORMED_OR_UNSUPPORTED
    assert diagnostic.key_id is None
    assert diagnostic.recoverable_automatically is False
    assert path.read_bytes() == original


def test_symlinked_authority_key_is_classified_unsafe_without_following(
    tmp_path,
):
    target = tmp_path / "outside-key.json"
    target.write_text(
        "{not-valid-json",
        encoding="utf-8",
    )

    path = tmp_path / "authority-state.key.json"
    path.symlink_to(target)

    before = target.read_bytes()

    diagnostic = diagnose_authority_state_key(path)

    assert diagnostic.status is AuthorityKeyRecoveryStatus.UNSAFE_STORAGE
    assert diagnostic.key_id is None
    assert diagnostic.recoverable_automatically is False
    assert path.is_symlink()
    assert target.read_bytes() == before


def test_non_regular_authority_key_is_classified_unsafe(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"
    path.mkdir()

    diagnostic = diagnose_authority_state_key(path)

    assert diagnostic.status is AuthorityKeyRecoveryStatus.UNSAFE_STORAGE
    assert diagnostic.key_id is None
    assert diagnostic.recoverable_automatically is False
    assert path.is_dir()


def test_broken_symlink_authority_key_is_unsafe_not_missing(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"
    path.symlink_to(tmp_path / "missing-target.json")

    diagnostic = diagnose_authority_state_key(path)

    assert diagnostic.status is AuthorityKeyRecoveryStatus.UNSAFE_STORAGE
    assert diagnostic.recoverable_automatically is False
    assert path.is_symlink()


def test_legacy_lifecycle_with_key_remains_classified_as_valid_legacy(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
    )

    diagnostic = diagnose_lifecycle_state(
        path,
        authority_key=key,
    )

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_LEGACY
    assert diagnostic.authenticated is False


def test_legacy_registry_with_key_remains_classified_as_valid_legacy(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")
    path = tmp_path / "registry.json"

    save_source_registry_state(
        path,
        SourceRegistryStateStore(),
    )

    diagnostic = diagnose_source_registry_state(
        path,
        authority_key=key,
    )

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_LEGACY
    assert diagnostic.authenticated is False


def test_malformed_authenticated_like_lifecycle_is_not_misclassified_key_required(
    tmp_path,
):
    path = tmp_path / "lifecycle.json"
    path.write_text(
        json.dumps(
            {
                "auth_version": 1,
                "context": "lifecycle",
                "key_id": "local-authority-v1",
            }
        ),
        encoding="utf-8",
    )

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.MALFORMED_OR_UNSUPPORTED
    assert diagnostic.authenticated is True


def test_authenticated_context_swap_is_classified_authentication_failed(
    tmp_path,
):
    key = generate_authority_state_key(tmp_path / "authority-state.key.json")

    registry_path = tmp_path / "registry.json"
    lifecycle_path = tmp_path / "lifecycle.json"

    save_source_registry_state(
        registry_path,
        SourceRegistryStateStore(),
        authority_key=key,
    )

    lifecycle_path.write_bytes(registry_path.read_bytes())

    diagnostic = diagnose_lifecycle_state(
        lifecycle_path,
        authority_key=key,
    )

    assert diagnostic.status is AuthorityStateRecoveryStatus.AUTHENTICATION_FAILED
    assert diagnostic.authenticated is True
    assert diagnostic.recoverable_automatically is False


def test_lifecycle_diagnostic_uses_one_hardened_state_snapshot(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.state_recovery as recovery_module

    path = tmp_path / "lifecycle.json"

    save_lifecycle_state(
        path,
        LifecycleStateStore(),
    )

    original_reader = recovery_module._read_lifecycle_state_bytes
    calls = 0

    def counted_reader(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_reader(*args, **kwargs)

    monkeypatch.setattr(
        recovery_module,
        "_read_lifecycle_state_bytes",
        counted_reader,
    )

    diagnostic = diagnose_lifecycle_state(path)

    assert diagnostic.status is AuthorityStateRecoveryStatus.VALID_LEGACY
    assert calls == 1
