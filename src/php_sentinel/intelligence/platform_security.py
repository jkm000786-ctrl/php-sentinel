from __future__ import annotations

import os
from dataclasses import dataclass


class PlatformSecurityCapabilityError(RuntimeError):
    """Raised when the host cannot provide required filesystem security semantics."""


@dataclass(frozen=True)
class FilesystemSecurityCapabilities:
    nofollow_open: bool
    directory_open: bool
    open_dir_fd: bool
    mkdir_dir_fd: bool
    stat_dir_fd: bool
    unlink_dir_fd: bool
    rename_dir_fd: bool
    stat_no_follow: bool

    @property
    def anchored_directory_traversal(self) -> bool:
        return (
            self.nofollow_open
            and self.directory_open
            and self.open_dir_fd
            and self.mkdir_dir_fd
            and self.stat_dir_fd
            and self.unlink_dir_fd
            and self.rename_dir_fd
            and self.stat_no_follow
        )

    @property
    def verified_cache_descriptor_access(self) -> bool:
        return self.nofollow_open and self.directory_open and self.open_dir_fd


def filesystem_security_capabilities() -> FilesystemSecurityCapabilities:
    supports_dir_fd = getattr(os, "supports_dir_fd", set())
    supports_follow_symlinks = getattr(
        os,
        "supports_follow_symlinks",
        set(),
    )

    return FilesystemSecurityCapabilities(
        nofollow_open=bool(getattr(os, "O_NOFOLLOW", 0)),
        directory_open=bool(getattr(os, "O_DIRECTORY", 0)),
        open_dir_fd=os.open in supports_dir_fd,
        mkdir_dir_fd=os.mkdir in supports_dir_fd,
        stat_dir_fd=os.stat in supports_dir_fd,
        unlink_dir_fd=os.unlink in supports_dir_fd,
        rename_dir_fd=os.rename in supports_dir_fd,
        stat_no_follow=os.stat in supports_follow_symlinks,
    )


def require_nofollow_open(
    *,
    operation: str,
) -> None:
    capabilities = filesystem_security_capabilities()

    if not capabilities.nofollow_open:
        raise PlatformSecurityCapabilityError(
            f"{operation} requires O_NOFOLLOW support; "
            "the current platform cannot provide the required no-follow open semantics."
        )


def require_anchored_directory_traversal(
    *,
    operation: str,
) -> None:
    capabilities = filesystem_security_capabilities()

    if capabilities.anchored_directory_traversal:
        return

    missing: list[str] = []

    if not capabilities.nofollow_open:
        missing.append("O_NOFOLLOW")

    if not capabilities.directory_open:
        missing.append("O_DIRECTORY")

    if not capabilities.open_dir_fd:
        missing.append("open(dir_fd)")

    if not capabilities.mkdir_dir_fd:
        missing.append("mkdir(dir_fd)")

    if not capabilities.stat_dir_fd:
        missing.append("stat(dir_fd)")

    if not capabilities.unlink_dir_fd:
        missing.append("unlink(dir_fd)")

    if not capabilities.rename_dir_fd:
        missing.append("rename(src_dir_fd/dst_dir_fd)")

    if not capabilities.stat_no_follow:
        missing.append("stat(follow_symlinks=False)")

    raise PlatformSecurityCapabilityError(
        f"{operation} requires descriptor-relative no-follow filesystem semantics "
        f"that are unavailable on this platform: {', '.join(missing)}."
    )


def require_verified_cache_descriptor_access(
    *,
    operation: str,
) -> None:
    capabilities = filesystem_security_capabilities()

    if capabilities.verified_cache_descriptor_access:
        return

    missing: list[str] = []

    if not capabilities.nofollow_open:
        missing.append("O_NOFOLLOW")

    if not capabilities.directory_open:
        missing.append("O_DIRECTORY")

    if not capabilities.open_dir_fd:
        missing.append("open(dir_fd)")

    raise PlatformSecurityCapabilityError(
        f"{operation} requires verified-cache descriptor security semantics "
        f"that are unavailable on this platform: {', '.join(missing)}."
    )
