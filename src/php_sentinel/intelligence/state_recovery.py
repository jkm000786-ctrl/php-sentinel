from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from php_sentinel.intelligence.lifecycle import (
    LifecycleStateStorageError,
    _read_lifecycle_state_bytes,
)
from php_sentinel.intelligence.registry_trust import (
    SourceRegistryStateStorageError,
    _read_source_registry_state_bytes,
)
from php_sentinel.intelligence.state_auth import (
    AuthorityStateAuthenticationError,
    verify_authority_state_envelope,
)
from php_sentinel.intelligence.state_key import (
    AuthorityStateKeyNotFoundError,
    AuthorityStateKeyStorageError,
    LoadedAuthorityStateKey,
    load_authority_state_key,
)
from php_sentinel.models.intelligence_lifecycle import LifecycleStateStore
from php_sentinel.models.registry_trust import SourceRegistryStateStore
from php_sentinel.models.state_auth import AuthorityStateEnvelope


class AuthorityStateRecoveryStatus(StrEnum):
    MISSING = "missing"
    VALID_AUTHENTICATED = "valid_authenticated"
    VALID_LEGACY = "valid_legacy"
    AUTHORITY_KEY_REQUIRED = "authority_key_required"
    AUTHENTICATION_FAILED = "authentication_failed"
    MALFORMED_OR_UNSUPPORTED = "malformed_or_unsupported"
    UNSAFE_STORAGE = "unsafe_storage"


class AuthorityKeyRecoveryStatus(StrEnum):
    MISSING = "missing"
    VALID = "valid"
    MALFORMED_OR_UNSUPPORTED = "malformed_or_unsupported"
    UNSAFE_STORAGE = "unsafe_storage"


@dataclass(frozen=True)
class AuthorityStateRecoveryDiagnostic:
    status: AuthorityStateRecoveryStatus
    path: Path
    context: str
    authenticated: bool | None
    recoverable_automatically: bool
    detail: str


@dataclass(frozen=True)
class AuthorityKeyRecoveryDiagnostic:
    status: AuthorityKeyRecoveryStatus
    path: Path
    key_id: str | None
    recoverable_automatically: bool
    detail: str


_AUTHENTICATED_ENVELOPE_FIELDS = frozenset(
    {
        "auth_version",
        "mac_b64",
        "context",
        "key_id",
    }
)


def _decode_json_payload(
    payload: bytes,
) -> Any:
    return json.loads(payload.decode("utf-8"))


def _looks_like_authenticated_envelope(
    data: Any,
) -> bool:
    return isinstance(data, dict) and bool(_AUTHENTICATED_ENVELOPE_FIELDS.intersection(data))


def _malformed_state_diagnostic(
    *,
    path: Path,
    context: str,
    authenticated: bool | None,
    detail: str,
) -> AuthorityStateRecoveryDiagnostic:
    return AuthorityStateRecoveryDiagnostic(
        status=AuthorityStateRecoveryStatus.MALFORMED_OR_UNSUPPORTED,
        path=path,
        context=context,
        authenticated=authenticated,
        recoverable_automatically=False,
        detail=detail,
    )


def _unsafe_state_diagnostic(
    *,
    path: Path,
    context: str,
    detail: str,
) -> AuthorityStateRecoveryDiagnostic:
    return AuthorityStateRecoveryDiagnostic(
        status=AuthorityStateRecoveryStatus.UNSAFE_STORAGE,
        path=path,
        context=context,
        authenticated=None,
        recoverable_automatically=False,
        detail=detail,
    )


def _storage_error_is_unsafe(
    message: str,
) -> bool:
    lowered = message.lower()

    return (
        "symbolic link" in lowered
        or "not a regular file" in lowered
        or "could not be opened safely" in lowered
        or "directory could not be opened" in lowered
    )


def _diagnose_state_payload(
    *,
    payload: bytes,
    path: Path,
    context: str,
    authority_key: LoadedAuthorityStateKey | None,
    state_model,
) -> AuthorityStateRecoveryDiagnostic:
    try:
        data = _decode_json_payload(payload)
    except (
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return _malformed_state_diagnostic(
            path=path,
            context=context,
            authenticated=None,
            detail=(
                f"{context.capitalize()} authority-state payload is unreadable, "
                "malformed, or unsupported."
            ),
        )

    authenticated_hint = _looks_like_authenticated_envelope(data)

    if not authenticated_hint:
        try:
            state_model.model_validate(data)
        except ValueError:
            return _malformed_state_diagnostic(
                path=path,
                context=context,
                authenticated=False,
                detail=(
                    f"{context.capitalize()} authority-state payload is malformed "
                    "or unsupported legacy state."
                ),
            )

        return AuthorityStateRecoveryDiagnostic(
            status=AuthorityStateRecoveryStatus.VALID_LEGACY,
            path=path,
            context=context,
            authenticated=False,
            recoverable_automatically=False,
            detail=(f"{context.capitalize()} authority-state file is valid legacy unsigned state."),
        )

    try:
        envelope = AuthorityStateEnvelope.model_validate(data)
    except ValueError:
        return _malformed_state_diagnostic(
            path=path,
            context=context,
            authenticated=True,
            detail=(
                f"{context.capitalize()} authority-state payload resembles an "
                "authenticated envelope but is malformed or unsupported."
            ),
        )

    if authority_key is None:
        return AuthorityStateRecoveryDiagnostic(
            status=AuthorityStateRecoveryStatus.AUTHORITY_KEY_REQUIRED,
            path=path,
            context=context,
            authenticated=True,
            recoverable_automatically=False,
            detail=(
                f"{context.capitalize()} authority-state is authenticated and "
                "requires its existing local authority-state key for verification."
            ),
        )

    try:
        verified_state = verify_authority_state_envelope(
            envelope,
            expected_context=context,
            expected_key_id=authority_key.key_id,
            key=authority_key.key,
        )
    except AuthorityStateAuthenticationError as exc:
        return AuthorityStateRecoveryDiagnostic(
            status=AuthorityStateRecoveryStatus.AUTHENTICATION_FAILED,
            path=path,
            context=context,
            authenticated=True,
            recoverable_automatically=False,
            detail=str(exc),
        )

    try:
        state_model.model_validate(verified_state)
    except ValueError:
        return _malformed_state_diagnostic(
            path=path,
            context=context,
            authenticated=True,
            detail=(
                f"{context.capitalize()} authority-state authenticated successfully "
                "but its embedded state schema is malformed or unsupported."
            ),
        )

    return AuthorityStateRecoveryDiagnostic(
        status=AuthorityStateRecoveryStatus.VALID_AUTHENTICATED,
        path=path,
        context=context,
        authenticated=True,
        recoverable_automatically=False,
        detail=(f"{context.capitalize()} authority-state authentication and validation succeeded."),
    )


def diagnose_lifecycle_state(
    path: Path | str,
    *,
    authority_key: LoadedAuthorityStateKey | None = None,
) -> AuthorityStateRecoveryDiagnostic:
    state_path = Path(path)

    try:
        payload = _read_lifecycle_state_bytes(state_path)
    except LifecycleStateStorageError as exc:
        message = str(exc)

        if _storage_error_is_unsafe(message):
            return _unsafe_state_diagnostic(
                path=state_path,
                context="lifecycle",
                detail=message,
            )

        return _malformed_state_diagnostic(
            path=state_path,
            context="lifecycle",
            authenticated=None,
            detail=message,
        )

    if payload is None:
        return AuthorityStateRecoveryDiagnostic(
            status=AuthorityStateRecoveryStatus.MISSING,
            path=state_path,
            context="lifecycle",
            authenticated=None,
            recoverable_automatically=False,
            detail="Lifecycle-state file does not exist.",
        )

    return _diagnose_state_payload(
        payload=payload,
        path=state_path,
        context="lifecycle",
        authority_key=authority_key,
        state_model=LifecycleStateStore,
    )


def diagnose_source_registry_state(
    path: Path | str,
    *,
    authority_key: LoadedAuthorityStateKey | None = None,
) -> AuthorityStateRecoveryDiagnostic:
    state_path = Path(path)

    try:
        payload = _read_source_registry_state_bytes(state_path)
    except SourceRegistryStateStorageError as exc:
        message = str(exc)

        if _storage_error_is_unsafe(message):
            return _unsafe_state_diagnostic(
                path=state_path,
                context="registry",
                detail=message,
            )

        return _malformed_state_diagnostic(
            path=state_path,
            context="registry",
            authenticated=None,
            detail=message,
        )

    if payload is None:
        return AuthorityStateRecoveryDiagnostic(
            status=AuthorityStateRecoveryStatus.MISSING,
            path=state_path,
            context="registry",
            authenticated=None,
            recoverable_automatically=False,
            detail="Source-registry state file does not exist.",
        )

    return _diagnose_state_payload(
        payload=payload,
        path=state_path,
        context="registry",
        authority_key=authority_key,
        state_model=SourceRegistryStateStore,
    )


def diagnose_authority_state_key(
    path: Path | str,
) -> AuthorityKeyRecoveryDiagnostic:
    key_path = Path(path)

    try:
        loaded = load_authority_state_key(key_path)
    except AuthorityStateKeyNotFoundError as exc:
        return AuthorityKeyRecoveryDiagnostic(
            status=AuthorityKeyRecoveryStatus.MISSING,
            path=key_path,
            key_id=None,
            recoverable_automatically=False,
            detail=str(exc),
        )
    except AuthorityStateKeyStorageError as exc:
        message = str(exc)

        if _storage_error_is_unsafe(message):
            status = AuthorityKeyRecoveryStatus.UNSAFE_STORAGE
        else:
            status = AuthorityKeyRecoveryStatus.MALFORMED_OR_UNSUPPORTED

        return AuthorityKeyRecoveryDiagnostic(
            status=status,
            path=key_path,
            key_id=None,
            recoverable_automatically=False,
            detail=message,
        )

    return AuthorityKeyRecoveryDiagnostic(
        status=AuthorityKeyRecoveryStatus.VALID,
        path=key_path,
        key_id=loaded.key_id,
        recoverable_automatically=False,
        detail="Authority-state key loaded and validated successfully.",
    )
