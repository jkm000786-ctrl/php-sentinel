from __future__ import annotations

import errno
import os

import pytest

import php_sentinel.intelligence.path_anchor as path_anchor_module
from php_sentinel.intelligence.path_anchor import (
    DirectoryAnchorError,
    close_directory_anchor,
    open_directory_anchor,
)


def test_absolute_nested_directory_is_created_component_by_component(
    tmp_path,
):
    target = tmp_path / "one" / "two" / "three"

    anchor = open_directory_anchor(
        target,
        create=True,
        mode=0o700,
    )

    assert anchor is not None

    try:
        assert target.is_dir()
        assert os.path.samefile(
            f"/proc/self/fd/{anchor.descriptor}",
            target,
        )
    finally:
        close_directory_anchor(anchor)


def test_missing_directory_returns_none_without_creation(
    tmp_path,
):
    target = tmp_path / "missing" / "nested"

    anchor = open_directory_anchor(
        target,
        create=False,
        mode=0o700,
    )

    assert anchor is None
    assert not target.exists()


def test_symlinked_ancestor_is_rejected(
    tmp_path,
):
    real_root = tmp_path / "real-root"
    real_root.mkdir()

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(
        real_root,
        target_is_directory=True,
    )

    with pytest.raises(
        DirectoryAnchorError,
        match="real directory|opened safely",
    ):
        open_directory_anchor(
            linked_root / "nested",
            create=True,
            mode=0o700,
        )

    assert not (real_root / "nested").exists()


def test_parent_traversal_is_rejected(
    tmp_path,
):
    target = tmp_path / "child" / ".." / "state"

    with pytest.raises(
        DirectoryAnchorError,
        match="Parent traversal is not allowed",
    ):
        open_directory_anchor(
            target,
            create=True,
            mode=0o700,
        )


def test_non_directory_ancestor_is_rejected(
    tmp_path,
):
    blocker = tmp_path / "blocker"
    blocker.write_text(
        "not-a-directory",
        encoding="utf-8",
    )

    with pytest.raises(
        DirectoryAnchorError,
        match="real directory|opened safely",
    ):
        open_directory_anchor(
            blocker / "nested",
            create=True,
            mode=0o700,
        )


def test_other_open_oserror_is_normalized(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "blocked"
    target.mkdir()

    real_open_child = path_anchor_module._open_child_directory

    def fail_target_component(
        parent_fd,
        component,
    ):
        if component == "blocked":
            raise PermissionError(
                errno.EACCES,
                "permission denied",
                component,
            )

        return real_open_child(
            parent_fd,
            component,
        )

    monkeypatch.setattr(
        path_anchor_module,
        "_open_child_directory",
        fail_target_component,
    )

    with pytest.raises(
        DirectoryAnchorError,
        match="could not be opened safely",
    ):
        open_directory_anchor(
            target,
            create=False,
            mode=0o700,
        )
