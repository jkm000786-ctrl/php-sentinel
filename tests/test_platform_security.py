from __future__ import annotations

from types import SimpleNamespace

import pytest

from php_sentinel.intelligence import platform_security


def test_current_platform_reports_anchored_security_capabilities():
    capabilities = platform_security.filesystem_security_capabilities()

    assert capabilities.nofollow_open
    assert capabilities.directory_open
    assert capabilities.open_dir_fd
    assert capabilities.mkdir_dir_fd
    assert capabilities.stat_dir_fd
    assert capabilities.unlink_dir_fd
    assert capabilities.rename_dir_fd
    assert capabilities.stat_no_follow
    assert capabilities.anchored_directory_traversal


def test_require_nofollow_open_fails_closed_when_missing(
    monkeypatch,
):
    monkeypatch.setattr(
        platform_security,
        "filesystem_security_capabilities",
        lambda: SimpleNamespace(
            nofollow_open=False,
        ),
    )

    with pytest.raises(
        platform_security.PlatformSecurityCapabilityError,
        match="requires O_NOFOLLOW support",
    ):
        platform_security.require_nofollow_open(
            operation="Test reader",
        )


def test_require_anchored_directory_traversal_reports_missing_capabilities(
    monkeypatch,
):
    monkeypatch.setattr(
        platform_security,
        "filesystem_security_capabilities",
        lambda: platform_security.FilesystemSecurityCapabilities(
            nofollow_open=False,
            directory_open=False,
            open_dir_fd=False,
            mkdir_dir_fd=False,
            stat_dir_fd=False,
            unlink_dir_fd=False,
            rename_dir_fd=False,
            stat_no_follow=False,
        ),
    )

    with pytest.raises(
        platform_security.PlatformSecurityCapabilityError,
        match="descriptor-relative no-follow filesystem semantics",
    ) as exc_info:
        platform_security.require_anchored_directory_traversal(
            operation="Authority-state traversal",
        )

    message = str(exc_info.value)

    assert "O_NOFOLLOW" in message
    assert "O_DIRECTORY" in message
    assert "open(dir_fd)" in message
    assert "rename(src_dir_fd/dst_dir_fd)" in message


def test_nofollow_capability_is_independent_from_anchored_traversal(
    monkeypatch,
):
    monkeypatch.setattr(
        platform_security,
        "filesystem_security_capabilities",
        lambda: platform_security.FilesystemSecurityCapabilities(
            nofollow_open=True,
            directory_open=False,
            open_dir_fd=False,
            mkdir_dir_fd=False,
            stat_dir_fd=False,
            unlink_dir_fd=False,
            rename_dir_fd=False,
            stat_no_follow=False,
        ),
    )

    platform_security.require_nofollow_open(
        operation="Standalone reader",
    )

    with pytest.raises(
        platform_security.PlatformSecurityCapabilityError,
    ):
        platform_security.require_anchored_directory_traversal(
            operation="Anchored state",
        )


def test_verified_cache_descriptor_capability_is_narrower_than_full_anchor(
    monkeypatch,
):
    monkeypatch.setattr(
        platform_security,
        "filesystem_security_capabilities",
        lambda: platform_security.FilesystemSecurityCapabilities(
            nofollow_open=True,
            directory_open=True,
            open_dir_fd=True,
            mkdir_dir_fd=False,
            stat_dir_fd=False,
            unlink_dir_fd=False,
            rename_dir_fd=False,
            stat_no_follow=False,
        ),
    )

    platform_security.require_verified_cache_descriptor_access(
        operation="Cache read",
    )

    with pytest.raises(
        platform_security.PlatformSecurityCapabilityError,
    ):
        platform_security.require_anchored_directory_traversal(
            operation="Authority state",
        )


def test_verified_cache_descriptor_capability_fails_closed(
    monkeypatch,
):
    monkeypatch.setattr(
        platform_security,
        "filesystem_security_capabilities",
        lambda: platform_security.FilesystemSecurityCapabilities(
            nofollow_open=False,
            directory_open=False,
            open_dir_fd=False,
            mkdir_dir_fd=True,
            stat_dir_fd=True,
            unlink_dir_fd=True,
            rename_dir_fd=True,
            stat_no_follow=True,
        ),
    )

    with pytest.raises(
        platform_security.PlatformSecurityCapabilityError,
        match="verified-cache descriptor security semantics",
    ) as exc_info:
        platform_security.require_verified_cache_descriptor_access(
            operation="Cache read",
        )

    message = str(exc_info.value)

    assert "O_NOFOLLOW" in message
    assert "O_DIRECTORY" in message
    assert "open(dir_fd)" in message
