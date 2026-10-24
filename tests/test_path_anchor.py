from __future__ import annotations

import errno
import os
from pathlib import Path

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


def test_current_directory_anchor_does_not_chmod_start_descriptor(
    monkeypatch,
):
    import php_sentinel.intelligence.path_anchor as path_anchor_module

    calls: list[tuple[int, int]] = []

    def record_fchmod(
        descriptor,
        mode,
    ):
        calls.append(
            (
                descriptor,
                mode,
            )
        )

    monkeypatch.setattr(
        path_anchor_module.os,
        "fchmod",
        record_fchmod,
    )

    anchor = open_directory_anchor(
        Path("."),
        create=False,
        mode=0o700,
    )

    assert anchor is not None

    try:
        assert calls == []
    finally:
        close_directory_anchor(anchor)


def test_root_directory_anchor_does_not_chmod_start_descriptor(
    monkeypatch,
):
    import php_sentinel.intelligence.path_anchor as path_anchor_module

    calls: list[tuple[int, int]] = []

    def record_fchmod(
        descriptor,
        mode,
    ):
        calls.append(
            (
                descriptor,
                mode,
            )
        )

    monkeypatch.setattr(
        path_anchor_module.os,
        "fchmod",
        record_fchmod,
    )

    anchor = open_directory_anchor(
        Path("/"),
        create=False,
        mode=0o700,
    )

    assert anchor is not None

    try:
        assert calls == []
    finally:
        close_directory_anchor(anchor)


def test_nonempty_directory_anchor_still_applies_requested_mode(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.path_anchor as path_anchor_module

    calls: list[tuple[int, int]] = []
    real_fchmod = path_anchor_module.os.fchmod

    def record_fchmod(
        descriptor,
        mode,
    ):
        calls.append(
            (
                descriptor,
                mode,
            )
        )
        return real_fchmod(
            descriptor,
            mode,
        )

    monkeypatch.setattr(
        path_anchor_module.os,
        "fchmod",
        record_fchmod,
    )

    target = tmp_path / "managed"

    anchor = open_directory_anchor(
        target,
        create=True,
        mode=0o700,
    )

    assert anchor is not None

    try:
        assert calls
        assert calls[-1][1] == 0o700
    finally:
        close_directory_anchor(anchor)


def test_anchor_fails_closed_when_platform_security_capability_is_missing(
    tmp_path,
    monkeypatch,
):
    from php_sentinel.intelligence.platform_security import (
        PlatformSecurityCapabilityError,
    )

    def deny_capability(
        *,
        operation,
    ):
        raise PlatformSecurityCapabilityError(f"{operation} is unavailable.")

    monkeypatch.setattr(
        path_anchor_module,
        "require_anchored_directory_traversal",
        deny_capability,
    )

    target = tmp_path / "state"

    with pytest.raises(
        path_anchor_module.DirectoryAnchorError,
        match="platform cannot provide the required filesystem security semantics",
    ):
        path_anchor_module.open_directory_anchor(
            target,
            create=True,
            mode=0o700,
        )

    assert not target.exists()


def test_anchor_mode_tightening_is_best_effort_after_secure_open(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "state"

    def deny_fchmod(
        descriptor,
        mode,
    ):
        raise OSError("mode bits unsupported")

    monkeypatch.setattr(
        path_anchor_module.os,
        "fchmod",
        deny_fchmod,
    )

    anchor = path_anchor_module.open_directory_anchor(
        target,
        create=True,
        mode=0o700,
    )

    assert anchor is not None
    assert target.is_dir()

    path_anchor_module.close_directory_anchor(anchor)
