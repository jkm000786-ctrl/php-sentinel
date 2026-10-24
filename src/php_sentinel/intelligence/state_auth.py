from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

from php_sentinel.intelligence.format_governance import (
    AuthorityFormatKind,
    require_current_writable_format,
)
from php_sentinel.models.state_auth import AuthorityStateEnvelope

AUTHORITY_STATE_AUTH_DOMAIN_V1 = b"PHP-SENTINEL-AUTHORITY-STATE-HMAC-V1\x00"

AUTHORITY_STATE_KEY_BYTES = 32

_CONTEXT_DOMAINS = {
    "lifecycle": b"LIFECYCLE\x00",
    "registry": b"REGISTRY\x00",
}


class AuthorityStateAuthenticationError(ValueError):
    """Raised when local authority-state authentication fails."""


def _validate_key(
    key: bytes,
) -> bytes:
    if not isinstance(key, bytes):
        raise TypeError("Authority-state authentication key must be bytes.")

    if len(key) != AUTHORITY_STATE_KEY_BYTES:
        raise ValueError("Authority-state authentication key must be exactly 32 bytes.")

    return key


def _state_payload(
    state: BaseModel | Mapping[str, Any],
) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        payload = state.model_dump(mode="json")
    elif isinstance(state, Mapping):
        payload = dict(state)
    else:
        raise TypeError("Authority-state payload must be a Pydantic model or mapping.")

    return json.loads(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    )


def authority_state_signing_bytes(
    *,
    auth_version: int,
    context: str,
    algorithm: str,
    key_id: str,
    state: BaseModel | Mapping[str, Any],
) -> bytes:
    try:
        context_domain = _CONTEXT_DOMAINS[context]
    except KeyError as exc:
        raise ValueError(f"Unsupported authority-state context: {context}.") from exc

    payload = {
        "algorithm": algorithm,
        "auth_version": auth_version,
        "context": context,
        "key_id": key_id,
        "state": _state_payload(state),
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return AUTHORITY_STATE_AUTH_DOMAIN_V1 + context_domain + canonical


def create_authority_state_envelope(
    *,
    context: str,
    key_id: str,
    key: bytes,
    state: BaseModel | Mapping[str, Any],
) -> AuthorityStateEnvelope:
    validated_key = _validate_key(key)
    normalized_state = _state_payload(state)

    placeholder = base64.b64encode(b"\x00" * hashlib.sha256().digest_size).decode("ascii")

    envelope = AuthorityStateEnvelope(
        context=context,
        key_id=key_id,
        state=normalized_state,
        mac_b64=placeholder,
    )

    require_current_writable_format(
        AuthorityFormatKind.AUTHORITY_STATE_ENVELOPE,
        envelope.auth_version,
    )

    mac = hmac.new(
        validated_key,
        authority_state_signing_bytes(
            auth_version=envelope.auth_version,
            context=envelope.context,
            algorithm=envelope.algorithm,
            key_id=envelope.key_id,
            state=envelope.state,
        ),
        hashlib.sha256,
    ).digest()

    return envelope.model_copy(
        update={
            "mac_b64": base64.b64encode(mac).decode("ascii"),
        }
    )


def verify_authority_state_envelope(
    envelope: AuthorityStateEnvelope,
    *,
    expected_context: str,
    expected_key_id: str,
    key: bytes,
) -> dict[str, Any]:
    validated_key = _validate_key(key)

    if envelope.context != expected_context:
        raise AuthorityStateAuthenticationError("Authority-state authentication context mismatch.")

    if envelope.key_id != expected_key_id:
        raise AuthorityStateAuthenticationError(
            "Authority-state authentication key identity mismatch."
        )

    supplied_mac = base64.b64decode(
        envelope.mac_b64,
        validate=True,
    )

    expected_mac = hmac.new(
        validated_key,
        authority_state_signing_bytes(
            auth_version=envelope.auth_version,
            context=envelope.context,
            algorithm=envelope.algorithm,
            key_id=envelope.key_id,
            state=envelope.state,
        ),
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(
        supplied_mac,
        expected_mac,
    ):
        raise AuthorityStateAuthenticationError("Authority-state authentication failed.")

    return dict(envelope.state)


def canonical_authority_state_envelope_bytes(
    envelope: AuthorityStateEnvelope,
) -> bytes:
    return (
        json.dumps(
            envelope.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")
