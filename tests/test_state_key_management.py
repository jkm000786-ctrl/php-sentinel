from __future__ import annotations

import json
import os
import stat

import pytest

from php_sentinel.intelligence.state_key import (
    AUTHORITY_KEY_FILE_MODE,
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
