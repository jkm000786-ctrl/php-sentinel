from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from php_sentinel.intelligence.platform_security import (
    PlatformSecurityCapabilityError,
    require_anchored_directory_traversal,
)


class DirectoryAnchorError(ValueError):
    """Raised when a directory path cannot be traversed without following links."""


@dataclass(frozen=True)
class DirectoryAnchor:
    descriptor: int
    path: Path


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW


def _path_components(path: Path) -> tuple[bool, list[str]]:
    if any(part == ".." for part in path.parts):
        raise DirectoryAnchorError(
            f"Parent traversal is not allowed in anchored directory paths: {path}."
        )

    absolute = path.is_absolute()

    if absolute:
        parts = [
            part
            for part in path.parts
            if part
            not in (
                path.anchor,
                "",
                ".",
            )
        ]
    else:
        parts = [part for part in path.parts if part not in ("", ".")]

    return absolute, parts


def _open_start_descriptor(
    *,
    absolute: bool,
) -> int:
    start = "/" if absolute else "."

    try:
        descriptor = os.open(
            start,
            _directory_flags(),
        )
    except OSError as exc:
        raise DirectoryAnchorError(
            f"Anchor root directory could not be opened safely: {start}."
        ) from exc

    try:
        status = os.fstat(descriptor)

        if not stat.S_ISDIR(status.st_mode):
            raise DirectoryAnchorError(f"Anchor root is not a directory: {start}.")

        return descriptor

    except Exception:
        os.close(descriptor)
        raise


def _open_child_directory(
    parent_fd: int,
    component: str,
) -> int:
    try:
        descriptor = os.open(
            component,
            _directory_flags(),
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        # Missing components are normal control flow for the outer walker,
        # which decides whether to create them or return None.
        raise
    except OSError as exc:
        if exc.errno in (
            errno.ELOOP,
            errno.ENOTDIR,
        ):
            raise DirectoryAnchorError(
                f"Directory component must be a real directory and not a symbolic link: {component}."
            ) from exc

        raise DirectoryAnchorError(
            f"Directory component could not be opened safely: {component}."
        ) from exc

    try:
        status = os.fstat(descriptor)

        if not stat.S_ISDIR(status.st_mode):
            raise DirectoryAnchorError(f"Directory component is not a directory: {component}.")

        return descriptor

    except Exception:
        os.close(descriptor)
        raise


def open_directory_anchor(
    path: Path | str,
    *,
    create: bool,
    mode: int,
) -> DirectoryAnchor | None:
    """
    Open one directory path without following symbolic links in any traversed
    component.

    Absolute paths are walked from an open descriptor for `/`.
    Relative paths are walked from an open descriptor for the current working
    directory.

    Missing components may be created one-at-a-time relative to an already-open
    parent descriptor. `..` is rejected rather than traversed.
    """
    directory = Path(path)

    try:
        require_anchored_directory_traversal(
            operation="Anchored directory traversal",
        )
    except PlatformSecurityCapabilityError as exc:
        raise DirectoryAnchorError(
            "Anchored directory traversal is unavailable because the current "
            "platform cannot provide the required filesystem security semantics."
        ) from exc

    absolute, parts = _path_components(directory)

    descriptor = _open_start_descriptor(
        absolute=absolute,
    )

    try:
        for component in parts:
            try:
                child_fd = _open_child_directory(
                    descriptor,
                    component,
                )
            except FileNotFoundError:
                if not create:
                    os.close(descriptor)
                    return None

                try:
                    os.mkdir(
                        component,
                        mode=mode,
                        dir_fd=descriptor,
                    )
                except FileExistsError:
                    # Another process may have created the component. It must
                    # still pass the same no-follow directory open below.
                    pass
                except OSError as exc:
                    raise DirectoryAnchorError(
                        f"Directory component could not be created safely: {component}."
                    ) from exc

                try:
                    child_fd = _open_child_directory(
                        descriptor,
                        component,
                    )
                except FileNotFoundError as exc:
                    raise DirectoryAnchorError(
                        f"Created directory component disappeared before reopen: {component}."
                    ) from exc
                except DirectoryAnchorError:
                    raise
                except OSError as exc:
                    raise DirectoryAnchorError(
                        f"Created directory component could not be reopened safely: {component}."
                    ) from exc
            except DirectoryAnchorError:
                raise
            except OSError as exc:
                # Keep the public traversal contract fail-closed even if a
                # lower-level implementation or test double raises a raw
                # operating-system error.
                raise DirectoryAnchorError(
                    f"Directory component could not be opened safely: {component}."
                ) from exc

            os.close(descriptor)
            descriptor = child_fd

        if parts:
            try:
                os.fchmod(
                    descriptor,
                    mode,
                )
            except OSError:
                # Some filesystems/platforms cannot enforce POSIX mode bits.
                pass

        return DirectoryAnchor(
            descriptor=descriptor,
            path=directory,
        )

    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def close_directory_anchor(
    anchor: DirectoryAnchor,
) -> None:
    os.close(anchor.descriptor)
