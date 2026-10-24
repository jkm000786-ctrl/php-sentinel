from __future__ import annotations

import base64
import json

import pytest

from php_sentinel.intelligence.state_auth import (
    AUTHORITY_STATE_AUTH_DOMAIN_V1,
    AuthorityStateAuthenticationError,
    authority_state_signing_bytes,
    canonical_authority_state_envelope_bytes,
    create_authority_state_envelope,
    verify_authority_state_envelope,
)
from php_sentinel.models.intelligence_lifecycle import LifecycleStateStore
from php_sentinel.models.registry_trust import SourceRegistryStateStore
from php_sentinel.models.state_auth import AuthorityStateEnvelope

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
KEY_ID = "local-authority-v1"


def test_lifecycle_state_round_trip_authenticates():
    state = LifecycleStateStore()

    envelope = create_authority_state_envelope(
        context="lifecycle",
        key_id=KEY_ID,
        key=KEY,
        state=state,
    )

    verified = verify_authority_state_envelope(
        envelope,
        expected_context="lifecycle",
        expected_key_id=KEY_ID,
        key=KEY,
    )

    assert verified == state.model_dump(mode="json")


def test_registry_state_round_trip_authenticates():
    state = SourceRegistryStateStore()

    envelope = create_authority_state_envelope(
        context="registry",
        key_id=KEY_ID,
        key=KEY,
        state=state,
    )

    verified = verify_authority_state_envelope(
        envelope,
        expected_context="registry",
        expected_key_id=KEY_ID,
        key=KEY,
    )

    assert verified == state.model_dump(mode="json")


def test_state_tampering_is_rejected():
    envelope = create_authority_state_envelope(
        context="lifecycle",
        key_id=KEY_ID,
        key=KEY,
        state=LifecycleStateStore(),
    )

    tampered_state = dict(envelope.state)
    tampered_state["store_version"] = 999

    tampered = envelope.model_copy(update={"state": tampered_state})

    with pytest.raises(
        AuthorityStateAuthenticationError,
        match="authentication failed",
    ):
        verify_authority_state_envelope(
            tampered,
            expected_context="lifecycle",
            expected_key_id=KEY_ID,
            key=KEY,
        )


def test_mac_tampering_is_rejected():
    envelope = create_authority_state_envelope(
        context="lifecycle",
        key_id=KEY_ID,
        key=KEY,
        state=LifecycleStateStore(),
    )

    raw = bytearray(base64.b64decode(envelope.mac_b64))
    raw[0] ^= 1

    tampered = envelope.model_copy(
        update={
            "mac_b64": base64.b64encode(bytes(raw)).decode("ascii"),
        }
    )

    with pytest.raises(
        AuthorityStateAuthenticationError,
        match="authentication failed",
    ):
        verify_authority_state_envelope(
            tampered,
            expected_context="lifecycle",
            expected_key_id=KEY_ID,
            key=KEY,
        )


def test_wrong_key_is_rejected():
    envelope = create_authority_state_envelope(
        context="lifecycle",
        key_id=KEY_ID,
        key=KEY,
        state=LifecycleStateStore(),
    )

    with pytest.raises(
        AuthorityStateAuthenticationError,
        match="authentication failed",
    ):
        verify_authority_state_envelope(
            envelope,
            expected_context="lifecycle",
            expected_key_id=KEY_ID,
            key=OTHER_KEY,
        )


def test_wrong_context_is_rejected():
    envelope = create_authority_state_envelope(
        context="lifecycle",
        key_id=KEY_ID,
        key=KEY,
        state=LifecycleStateStore(),
    )

    with pytest.raises(
        AuthorityStateAuthenticationError,
        match="context mismatch",
    ):
        verify_authority_state_envelope(
            envelope,
            expected_context="registry",
            expected_key_id=KEY_ID,
            key=KEY,
        )


def test_wrong_key_identity_is_rejected():
    envelope = create_authority_state_envelope(
        context="registry",
        key_id=KEY_ID,
        key=KEY,
        state=SourceRegistryStateStore(),
    )

    with pytest.raises(
        AuthorityStateAuthenticationError,
        match="key identity mismatch",
    ):
        verify_authority_state_envelope(
            envelope,
            expected_context="registry",
            expected_key_id="other-authority-key",
            key=KEY,
        )


def test_contexts_are_domain_separated():
    state = {"store_version": 1}

    lifecycle = authority_state_signing_bytes(
        auth_version=1,
        context="lifecycle",
        algorithm="hmac-sha256",
        key_id=KEY_ID,
        state=state,
    )

    registry = authority_state_signing_bytes(
        auth_version=1,
        context="registry",
        algorithm="hmac-sha256",
        key_id=KEY_ID,
        state=state,
    )

    assert lifecycle != registry
    assert lifecycle.startswith(AUTHORITY_STATE_AUTH_DOMAIN_V1)
    assert registry.startswith(AUTHORITY_STATE_AUTH_DOMAIN_V1)


def test_canonical_envelope_bytes_are_deterministic():
    envelope = create_authority_state_envelope(
        context="lifecycle",
        key_id=KEY_ID,
        key=KEY,
        state=LifecycleStateStore(),
    )

    first = canonical_authority_state_envelope_bytes(envelope)
    second = canonical_authority_state_envelope_bytes(envelope)

    assert first == second

    parsed = AuthorityStateEnvelope.model_validate(json.loads(first.decode("utf-8")))

    assert parsed == envelope


def test_key_must_be_exactly_32_bytes():
    with pytest.raises(
        ValueError,
        match="exactly 32 bytes",
    ):
        create_authority_state_envelope(
            context="lifecycle",
            key_id=KEY_ID,
            key=b"short",
            state=LifecycleStateStore(),
        )


def test_envelope_rejects_noncanonical_key_identity():
    valid_mac = base64.b64encode(b"\x00" * 32).decode("ascii")

    with pytest.raises(ValueError):
        AuthorityStateEnvelope(
            context="lifecycle",
            key_id="bad|key",
            state={},
            mac_b64=valid_mac,
        )


def test_envelope_rejects_invalid_mac_length():
    with pytest.raises(
        ValueError,
        match="exactly 32 bytes",
    ):
        AuthorityStateEnvelope(
            context="lifecycle",
            key_id=KEY_ID,
            state={},
            mac_b64=base64.b64encode(b"\x00" * 31).decode("ascii"),
        )
