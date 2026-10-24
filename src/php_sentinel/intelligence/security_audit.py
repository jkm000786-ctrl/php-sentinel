from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from pydantic import ValidationError

from php_sentinel.intelligence.path_anchor import (
    DirectoryAnchor,
    DirectoryAnchorError,
    close_directory_anchor,
    open_directory_anchor,
)
from php_sentinel.intelligence.platform_security import (
    PlatformSecurityCapabilityError,
    require_nofollow_open,
)
from php_sentinel.models.security_audit import SecurityAuditEvent

SECURITY_AUDIT_FILE_MODE = 0o600
SECURITY_AUDIT_MAX_BYTES = 8 * 1024 * 1024
SECURITY_AUDIT_MAX_EVENT_BYTES = 16 * 1024


class SecurityAuditStorageError(RuntimeError):
    """Raised when the descriptive security-audit stream cannot be handled safely."""


def _canonical_event_bytes(
    event: SecurityAuditEvent,
) -> bytes:
    payload = (
        json.dumps(
            event.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    if len(payload) > SECURITY_AUDIT_MAX_EVENT_BYTES:
        raise SecurityAuditStorageError(
            "Security audit event exceeds the maximum allowed serialized size."
        )

    return payload


def _require_secure_audit_open() -> None:
    try:
        require_nofollow_open(
            operation="Security audit log access",
        )
    except PlatformSecurityCapabilityError as exc:
        raise SecurityAuditStorageError(str(exc)) from exc


def _audit_basename(
    audit_path: Path,
) -> str:
    name = audit_path.name

    if name in (
        "",
        ".",
        "..",
    ):
        raise SecurityAuditStorageError(f"Security audit path must identify a file: {audit_path}.")

    return name


def _open_audit_parent(
    audit_path: Path,
    *,
    create: bool,
) -> DirectoryAnchor | None:
    try:
        return open_directory_anchor(
            audit_path.parent,
            create=create,
            mode=0o700,
        )
    except DirectoryAnchorError as exc:
        raise SecurityAuditStorageError(
            f"Security audit parent path could not be anchored safely: {audit_path.parent}."
        ) from exc


def append_security_audit_event(
    path: Path | str,
    event: SecurityAuditEvent,
) -> None:
    """
    Append one descriptive security event.

    The audit stream is never an authority input. Failure to write this file
    must be surfaced to the caller, but reading or trusting this file must
    never influence signer trust, rollback state, registry authority, or
    activation decisions.
    """
    audit_path = Path(path)
    basename = _audit_basename(audit_path)
    payload = _canonical_event_bytes(event)

    _require_secure_audit_open()

    parent_anchor = _open_audit_parent(
        audit_path,
        create=True,
    )

    if parent_anchor is None:
        raise SecurityAuditStorageError(
            f"Security audit parent path could not be created safely: {audit_path.parent}."
        )

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW

    descriptor: int | None = None

    try:
        descriptor = os.open(
            basename,
            flags,
            SECURITY_AUDIT_FILE_MODE,
            dir_fd=parent_anchor.descriptor,
        )

        status = os.fstat(descriptor)

        if not stat.S_ISREG(status.st_mode):
            raise SecurityAuditStorageError(
                f"Security audit path is not a regular file: {audit_path}."
            )

        try:
            os.fchmod(
                descriptor,
                SECURITY_AUDIT_FILE_MODE,
            )
        except OSError:
            pass

        if status.st_size + len(payload) > SECURITY_AUDIT_MAX_BYTES:
            raise SecurityAuditStorageError("Security audit log exceeds the maximum allowed size.")

        view = memoryview(payload)
        written_total = 0

        while written_total < len(payload):
            written = os.write(
                descriptor,
                view[written_total:],
            )

            if written <= 0:
                raise SecurityAuditStorageError("Security audit append made no forward progress.")

            written_total += written

        os.fsync(descriptor)

        try:
            os.fsync(parent_anchor.descriptor)
        except OSError:
            # Directory fsync is best-effort; file durability remains required.
            pass

    except SecurityAuditStorageError:
        raise
    except OSError as exc:
        raise SecurityAuditStorageError(f"Security audit append failed: {audit_path}.") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

        close_directory_anchor(parent_anchor)


def read_security_audit_events(
    path: Path | str,
) -> list[SecurityAuditEvent]:
    audit_path = Path(path)
    basename = _audit_basename(audit_path)

    _require_secure_audit_open()

    parent_anchor = _open_audit_parent(
        audit_path,
        create=False,
    )

    if parent_anchor is None:
        return []

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    descriptor: int | None = None

    try:
        descriptor = os.open(
            basename,
            flags,
            dir_fd=parent_anchor.descriptor,
        )

        status = os.fstat(descriptor)

        if not stat.S_ISREG(status.st_mode):
            raise SecurityAuditStorageError(
                f"Security audit path is not a regular file: {audit_path}."
            )

        if status.st_size > SECURITY_AUDIT_MAX_BYTES:
            raise SecurityAuditStorageError("Security audit log exceeds the maximum allowed size.")

        chunks: list[bytes] = []
        total = 0

        while True:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    SECURITY_AUDIT_MAX_BYTES + 1 - total,
                ),
            )

            if not chunk:
                break

            total += len(chunk)

            if total > SECURITY_AUDIT_MAX_BYTES:
                raise SecurityAuditStorageError(
                    "Security audit log exceeds the maximum allowed size."
                )

            chunks.append(chunk)

        payload = b"".join(chunks)

    except FileNotFoundError:
        return []
    except SecurityAuditStorageError:
        raise
    except OSError as exc:
        raise SecurityAuditStorageError(f"Security audit read failed: {audit_path}.") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

        close_directory_anchor(parent_anchor)

    if not payload:
        return []

    events: list[SecurityAuditEvent] = []

    for line_number, line in enumerate(
        payload.splitlines(),
        start=1,
    ):
        if not line:
            continue

        if len(line) > SECURITY_AUDIT_MAX_EVENT_BYTES:
            raise SecurityAuditStorageError(
                f"Security audit event on line {line_number} exceeds the maximum allowed size."
            )

        try:
            data = json.loads(line.decode("utf-8"))
            events.append(SecurityAuditEvent.model_validate(data))
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValidationError,
        ) as exc:
            raise SecurityAuditStorageError(
                f"Security audit event on line {line_number} is malformed or unsupported."
            ) from exc

    return events
