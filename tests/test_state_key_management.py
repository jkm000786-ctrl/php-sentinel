from __future__ import annotations

import json
import os
import stat

import pytest

from php_sentinel.intelligence.state_key import (
    AUTHORITY_KEY_FILE_MODE,
    AuthorityStateKeyNotFoundError,
    AuthorityStateKeyStorageError,
    generate_authority_state_key,
    load_authority_state_key,
    load_or_create_authority_state_key,
)


def test_generate_and_load_authority_state_key(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    created = generate_authority_state_key(
        path,
        key_id="test-authority-v1",
    )

    loaded = load_authority_state_key(path)

    assert loaded == created
    assert loaded.key_id == "test-authority-v1"
    assert len(loaded.key) == 32


def test_key_generation_is_exclusive(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    first = generate_authority_state_key(path)

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="already exists",
    ):
        generate_authority_state_key(path)

    assert load_authority_state_key(path) == first


def test_load_or_create_reuses_existing_key(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    first = load_or_create_authority_state_key(path)

    second = load_or_create_authority_state_key(path)

    assert second == first


def test_missing_key_fails_closed_on_direct_load(
    tmp_path,
):
    path = tmp_path / "missing.key.json"

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="does not exist",
    ):
        load_authority_state_key(path)


def test_symlinked_key_is_rejected(
    tmp_path,
):
    target = tmp_path / "real-key.json"
    link = tmp_path / "authority-state.key.json"

    generate_authority_state_key(target)

    link.symlink_to(target)

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="symbolic link|opened safely",
    ):
        load_authority_state_key(link)


def test_non_regular_key_is_rejected(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"
    path.mkdir()

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="regular file|opened safely",
    ):
        load_authority_state_key(path)


def test_malformed_key_json_is_rejected(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    path.write_text(
        "{not-json",
        encoding="utf-8",
    )

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="malformed or unsupported",
    ):
        load_authority_state_key(path)


def test_invalid_key_length_is_rejected(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    path.write_text(
        json.dumps(
            {
                "key_file_version": 1,
                "key_id": "local-authority-v1",
                "algorithm": "hmac-sha256",
                "key_b64": "c2hvcnQ=",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="malformed or unsupported",
    ):
        load_authority_state_key(path)


def test_invalid_key_id_is_rejected(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    created = generate_authority_state_key(
        path,
        key_id="canonical-key",
    )

    data = json.loads(path.read_text(encoding="utf-8"))

    data["key_id"] = "bad|key"

    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="malformed or unsupported",
    ):
        load_authority_state_key(path)

    assert len(created.key) == 32


def test_generated_key_file_mode_is_owner_only(
    tmp_path,
):
    if os.name != "posix":
        pytest.skip("POSIX permission semantics required.")

    path = tmp_path / "authority-state.key.json"

    generate_authority_state_key(path)

    mode = stat.S_IMODE(path.stat().st_mode)

    assert mode == AUTHORITY_KEY_FILE_MODE


def test_loading_key_restricts_mode_when_supported(
    tmp_path,
):
    if os.name != "posix":
        pytest.skip("POSIX permission semantics required.")

    path = tmp_path / "authority-state.key.json"

    generate_authority_state_key(path)

    path.chmod(0o644)

    load_authority_state_key(path)

    mode = stat.S_IMODE(path.stat().st_mode)

    assert mode == AUTHORITY_KEY_FILE_MODE


def test_key_material_has_random_entropy(
    tmp_path,
):
    first = generate_authority_state_key(tmp_path / "first.json")

    second = generate_authority_state_key(tmp_path / "second.json")

    assert first.key != second.key


def test_key_generation_rejects_symlinked_ancestor_directory(
    tmp_path,
):
    real_root = tmp_path / "real-root"
    real_root.mkdir()

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(
        real_root,
        target_is_directory=True,
    )

    path = linked_root / "nested" / "authority-state.key.json"

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="directory could not be opened safely",
    ):
        generate_authority_state_key(path)

    assert not (real_root / "nested").exists()


def test_key_load_rejects_symlinked_ancestor_directory(
    tmp_path,
):
    real_root = tmp_path / "real-root"
    real_root.mkdir()

    real_key = real_root / "authority-state.key.json"

    generate_authority_state_key(real_key)

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(
        real_root,
        target_is_directory=True,
    )

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="directory could not be opened safely",
    ):
        load_authority_state_key(linked_root / "authority-state.key.json")


def test_key_parent_traversal_is_rejected(
    tmp_path,
):
    path = tmp_path / "child" / ".." / "authority-state.key.json"

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="directory could not be opened safely",
    ):
        generate_authority_state_key(path)


def test_nested_key_directories_are_created_component_by_component(
    tmp_path,
):
    path = tmp_path / "one" / "two" / "three" / "authority-state.key.json"

    created = generate_authority_state_key(
        path,
        key_id="nested-authority",
    )

    loaded = load_authority_state_key(path)

    assert loaded == created
    assert loaded.key_id == "nested-authority"


def test_missing_key_uses_specific_not_found_error(
    tmp_path,
):
    path = tmp_path / "missing-authority-state.key.json"

    with pytest.raises(
        AuthorityStateKeyNotFoundError,
        match="does not exist",
    ):
        load_authority_state_key(path)


def test_load_or_create_creates_only_when_key_is_missing(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    created = load_or_create_authority_state_key(
        path,
        key_id="created-from-missing",
    )

    loaded = load_authority_state_key(path)

    assert loaded == created
    assert loaded.key_id == "created-from-missing"


def test_load_or_create_does_not_replace_malformed_existing_key(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"

    original = b"{not-valid-json"
    path.write_bytes(original)

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="malformed or unsupported",
    ):
        load_or_create_authority_state_key(path)

    assert path.read_bytes() == original


def test_load_or_create_does_not_replace_symlinked_key(
    tmp_path,
):
    target = tmp_path / "real-key.json"
    target.write_text(
        "{not-valid-json",
        encoding="utf-8",
    )

    link = tmp_path / "authority-state.key.json"
    link.symlink_to(target)

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="symbolic link|opened safely",
    ):
        load_or_create_authority_state_key(link)

    assert link.is_symlink()
    assert target.read_text(encoding="utf-8") == "{not-valid-json"


def test_load_or_create_does_not_replace_non_regular_key(
    tmp_path,
):
    path = tmp_path / "authority-state.key.json"
    path.mkdir()

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="regular file|opened safely",
    ):
        load_or_create_authority_state_key(path)

    assert path.is_dir()


def test_oversized_authority_key_file_fails_closed(
    tmp_path,
):
    from php_sentinel.intelligence.state_key import (
        AUTHORITY_KEY_FILE_MAX_BYTES,
        AuthorityStateKeyStorageError,
        load_authority_state_key,
    )

    path = tmp_path / "authority-state.key.json"
    path.write_bytes(b"{" + (b"x" * AUTHORITY_KEY_FILE_MAX_BYTES))

    with pytest.raises(
        AuthorityStateKeyStorageError,
        match="maximum allowed size",
    ):
        load_authority_state_key(path)


def test_key_mode_tightening_failure_is_best_effort(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.state_key as state_key_module

    path = tmp_path / "state" / "authority-state.key.json"

    def deny_fchmod(
        descriptor,
        mode,
    ):
        raise OSError("mode bits unsupported")

    monkeypatch.setattr(
        state_key_module.os,
        "fchmod",
        deny_fchmod,
    )

    generated = state_key_module.generate_authority_state_key(path)

    assert generated.key
    assert path.is_file()

    loaded = state_key_module.load_authority_state_key(path)

    assert loaded == generated


def test_key_parent_directory_fsync_failure_is_best_effort(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.state_key as state_key_module

    path = tmp_path / "state" / "authority-state.key.json"
    real_fsync = state_key_module.os.fsync

    def selective_fsync(descriptor):
        status = state_key_module.os.fstat(descriptor)

        if state_key_module.stat.S_ISDIR(status.st_mode):
            raise OSError("directory fsync unsupported")

        return real_fsync(descriptor)

    monkeypatch.setattr(
        state_key_module.os,
        "fsync",
        selective_fsync,
    )

    generated = state_key_module.generate_authority_state_key(path)

    assert generated.key
    assert path.is_file()

    loaded = state_key_module.load_authority_state_key(path)

    assert loaded == generated
