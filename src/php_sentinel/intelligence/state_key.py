from __future__ import annotations

import base64
import errno
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from php_sentinel.models.state_key import AuthorityStateKeyRecord

DEFAULT_AUTHORITY_STATE_KEY_PATH = (
    Path.home() / ".local" / "state" / "php-sentinel" / "authority-state.key.json"
)

AUTHORITY_KEY_DIRECTORY_MODE = 0o700
AUTHORITY_KEY_FILE_MODE = 0o600
AUTHORITY_KEY_BYTES = 32


class AuthorityStateKeyStorageError(ValueError):
    """Raised when local authority-state key storage is unsafe or invalid."""


def authority_state_key_path_for_state(
    state_path: Path | str,
) -> Path:
    """Return the local authentication key path for one authority-state file."""
    path = Path(state_path)

    return path.parent / "authority-state.key.json"


@dataclass(frozen=True)
class LoadedAuthorityStateKey:
    key_id: str
    key: bytes


def _read_descriptor_bytes(
    descriptor: int,
    *,
    chunk_size: int = 64 * 1024,
) -> bytes:
    chunks: list[bytes] = []

    while True:
        chunk = os.read(
            descriptor,
            chunk_size,
        )

        if not chunk:
            break

        chunks.append(chunk)

    return b"".join(chunks)


def _secure_parent_directory(
    path: Path,
) -> None:
    parent = path.parent

    parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=AUTHORITY_KEY_DIRECTORY_MODE,
    )

    try:
        os.chmod(
            parent,
            AUTHORITY_KEY_DIRECTORY_MODE,
        )
    except OSError:
        # Some filesystems cannot enforce POSIX mode bits.
        pass


def _read_authority_key_bytes(
    path: Path,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    try:
        descriptor = os.open(
            path,
            flags,
        )
    except FileNotFoundError:
        raise AuthorityStateKeyStorageError(
            f"Authority-state key file does not exist: {path}."
        ) from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AuthorityStateKeyStorageError(
                f"Authority-state key file must not be a symbolic link: {path}."
            ) from exc

        raise AuthorityStateKeyStorageError(
            f"Authority-state key file could not be opened safely: {path}."
        ) from exc

    try:
        status = os.fstat(descriptor)

        if not stat.S_ISREG(status.st_mode):
            raise AuthorityStateKeyStorageError(
                f"Authority-state key path is not a regular file: {path}."
            )

        try:
            os.fchmod(
                descriptor,
                AUTHORITY_KEY_FILE_MODE,
            )
        except OSError:
            pass

        return _read_descriptor_bytes(descriptor)

    finally:
        os.close(descriptor)


def load_authority_state_key(
    path: Path | str = DEFAULT_AUTHORITY_STATE_KEY_PATH,
) -> LoadedAuthorityStateKey:
    key_path = Path(path)

    try:
        payload = _read_authority_key_bytes(
            key_path,
        )

        data = json.loads(payload.decode("utf-8"))

        record = AuthorityStateKeyRecord.model_validate(data)

        key = base64.b64decode(
            record.key_b64,
            validate=True,
        )

        if len(key) != AUTHORITY_KEY_BYTES:
            raise AuthorityStateKeyStorageError(
                "Authority-state key must decode to exactly 32 bytes."
            )

        return LoadedAuthorityStateKey(
            key_id=record.key_id,
            key=key,
        )

    except AuthorityStateKeyStorageError:
        raise
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise AuthorityStateKeyStorageError(
            f"Authority-state key file is malformed or unsupported: {key_path}."
        ) from exc


def _canonical_key_record_bytes(
    record: AuthorityStateKeyRecord,
) -> bytes:
    return (
        json.dumps(
            record.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def generate_authority_state_key(
    path: Path | str = DEFAULT_AUTHORITY_STATE_KEY_PATH,
    *,
    key_id: str = "local-authority-v1",
) -> LoadedAuthorityStateKey:
    key_path = Path(path)

    _secure_parent_directory(
        key_path,
    )

    key = os.urandom(
        AUTHORITY_KEY_BYTES,
    )

    record = AuthorityStateKeyRecord(
        key_id=key_id,
        key_b64=base64.b64encode(key).decode("ascii"),
    )

    payload = _canonical_key_record_bytes(record)

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    descriptor: int | None = None

    try:
        descriptor = os.open(
            key_path,
            flags,
            AUTHORITY_KEY_FILE_MODE,
        )

        status = os.fstat(descriptor)

        if not stat.S_ISREG(status.st_mode):
            raise AuthorityStateKeyStorageError(
                f"Authority-state key path is not a regular file: {key_path}."
            )

        try:
            os.fchmod(
                descriptor,
                AUTHORITY_KEY_FILE_MODE,
            )
        except OSError:
            pass

        offset = 0

        while offset < len(payload):
            written = os.write(
                descriptor,
                payload[offset:],
            )

            if written <= 0:
                raise AuthorityStateKeyStorageError(
                    "Authority-state key file write made no progress."
                )

            offset += written

        os.fsync(descriptor)

    except FileExistsError:
        raise AuthorityStateKeyStorageError(
            f"Authority-state key file already exists: {key_path}."
        ) from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AuthorityStateKeyStorageError(
                f"Authority-state key file must not be a symbolic link: {key_path}."
            ) from exc

        raise AuthorityStateKeyStorageError(
            f"Authority-state key file could not be created safely: {key_path}."
        ) from exc

    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        directory_fd = os.open(
            key_path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        directory_fd = None

    if directory_fd is not None:
        try:
            try:
                os.fsync(directory_fd)
            except OSError:
                pass
        finally:
            os.close(directory_fd)

    return LoadedAuthorityStateKey(
        key_id=record.key_id,
        key=key,
    )


def load_or_create_authority_state_key(
    path: Path | str = DEFAULT_AUTHORITY_STATE_KEY_PATH,
    *,
    key_id: str = "local-authority-v1",
) -> LoadedAuthorityStateKey:
    key_path = Path(path)

    try:
        return load_authority_state_key(
            key_path,
        )
    except AuthorityStateKeyStorageError:
        try:
            return generate_authority_state_key(
                key_path,
                key_id=key_id,
            )
        except AuthorityStateKeyStorageError:
            # Creation may have raced with another process. Re-read only after
            # exclusive creation failed.
            return load_authority_state_key(
                key_path,
            )
