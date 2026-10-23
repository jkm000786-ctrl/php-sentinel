from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from php_sentinel.models.intelligence_trust import (
    SignerDelegation,
    TrustStore,
)

DELEGATION_SIGNATURE_DOMAIN_V1 = b"PHP-SENTINEL-SIGNER-DELEGATION-V1\x00"

ED25519_PRIVATE_KEY_BYTES = 32
ED25519_PUBLIC_KEY_BYTES = 32


def delegation_signing_payload(
    delegation: SignerDelegation,
) -> dict[str, object]:
    return {
        "delegation_version": (delegation.delegation_version),
        "context": delegation.context,
        "predecessor_signer_id": (delegation.predecessor_signer_id),
        "successor_signer_id": (delegation.successor_signer_id),
        "successor_public_key_b64": (delegation.successor_public_key_b64),
        "sequence": delegation.sequence,
        "minimum_successor_generation": (delegation.minimum_successor_generation),
        "issued_at": (delegation.issued_at.isoformat()),
        "expires_at": (delegation.expires_at.isoformat()),
        "algorithm": delegation.algorithm,
    }


def delegation_signing_bytes(
    delegation: SignerDelegation,
) -> bytes:
    canonical = json.dumps(
        delegation_signing_payload(delegation),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return DELEGATION_SIGNATURE_DOMAIN_V1 + canonical


def create_signed_signer_delegation(
    *,
    context: str,
    predecessor_signer_id: str,
    predecessor_private_key_b64: str,
    successor_signer_id: str,
    successor_public_key_b64: str,
    sequence: int,
    minimum_successor_generation: int,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    validity_days: int = 30,
) -> SignerDelegation:
    private_bytes = base64.b64decode(
        predecessor_private_key_b64,
        validate=True,
    )

    if len(private_bytes) != ED25519_PRIVATE_KEY_BYTES:
        raise ValueError("Delegation predecessor private key must decode to exactly 32 bytes.")

    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

    issued = issued_at or datetime.now(UTC)

    expiry = expires_at or (issued + timedelta(days=validity_days))

    placeholder = base64.b64encode(b"\x00" * 64).decode("ascii")

    delegation = SignerDelegation(
        context=context,
        predecessor_signer_id=(predecessor_signer_id),
        successor_signer_id=(successor_signer_id),
        successor_public_key_b64=(successor_public_key_b64),
        sequence=sequence,
        minimum_successor_generation=(minimum_successor_generation),
        issued_at=issued,
        expires_at=expiry,
        algorithm="ed25519",
        signature_b64=placeholder,
    )

    signature = private_key.sign(delegation_signing_bytes(delegation))

    return delegation.model_copy(
        update={"signature_b64": (base64.b64encode(signature).decode("ascii"))}
    )


def verify_signer_delegation(
    *,
    delegation: SignerDelegation,
    trust_store: TrustStore,
    expected_context: str,
    successor_signer_id: str,
    successor_public_key_b64: str,
    now: datetime | None = None,
) -> bool:
    """
    Verify one direct predecessor -> successor delegation.

    Both keys must already exist as enabled local trust anchors.
    The delegation can narrow/authorize rotation but cannot add a key.
    """

    current_time = now or datetime.now(UTC)

    if delegation.context != expected_context:
        return False

    if delegation.successor_signer_id != successor_signer_id:
        return False

    if delegation.successor_public_key_b64 != successor_public_key_b64:
        return False

    if delegation.algorithm != "ed25519":
        return False

    if current_time < delegation.issued_at:
        return False

    if current_time >= delegation.expires_at:
        return False

    predecessor = next(
        (
            item
            for item in trust_store.signers
            if (item.signer_id == delegation.predecessor_signer_id and item.enabled)
        ),
        None,
    )

    successor = next(
        (
            item
            for item in trust_store.signers
            if (item.signer_id == successor_signer_id and item.enabled)
        ),
        None,
    )

    if predecessor is None or successor is None:
        return False

    if successor.public_key_b64 != successor_public_key_b64:
        return False

    if predecessor.algorithm != "ed25519" or successor.algorithm != "ed25519":
        return False

    try:
        predecessor_public = base64.b64decode(
            predecessor.public_key_b64,
            validate=True,
        )

        if len(predecessor_public) != ED25519_PUBLIC_KEY_BYTES:
            return False

        signature = base64.b64decode(
            delegation.signature_b64,
            validate=True,
        )

        public_key = Ed25519PublicKey.from_public_bytes(predecessor_public)

        public_key.verify(
            signature,
            delegation_signing_bytes(delegation),
        )

    except (
        ValueError,
        InvalidSignature,
    ):
        return False

    return True


def resolve_authorized_predecessors(
    *,
    trust_store: TrustStore,
    successor_signer_id: str,
    successor_public_key_b64: str,
    context: str,
    now: datetime | None = None,
) -> tuple[
    list[str],
    dict[str, int],
]:
    """
    Resolve direct cryptographic predecessor authorizations.

    Chains are deliberately bounded to one hop in Phase 22. A future
    multi-hop design must introduce explicit chain-depth and revocation
    semantics rather than recursively trusting arbitrary delegation.
    """

    candidates = [
        item
        for item in trust_store.delegations
        if (item.context == context and item.successor_signer_id == successor_signer_id)
    ]

    grouped: dict[
        str,
        list[SignerDelegation],
    ] = {}

    for item in candidates:
        grouped.setdefault(
            item.predecessor_signer_id,
            [],
        ).append(item)

    authorized: list[str] = []
    minimum_generations: dict[
        str,
        int,
    ] = {}

    for predecessor_id, items in grouped.items():
        # TrustStore rejects duplicate identity tuples. Select only the
        # highest sequence that is cryptographically valid.
        valid = [
            item
            for item in sorted(
                items,
                key=lambda value: (
                    -value.sequence,
                    value.minimum_successor_generation,
                    value.signature_b64,
                ),
            )
            if verify_signer_delegation(
                delegation=item,
                trust_store=trust_store,
                expected_context=context,
                successor_signer_id=(successor_signer_id),
                successor_public_key_b64=(successor_public_key_b64),
                now=now,
            )
        ]

        if not valid:
            continue

        selected = valid[0]

        authorized.append(predecessor_id)

        minimum_generations[predecessor_id] = selected.minimum_successor_generation

    return (
        sorted(authorized),
        minimum_generations,
    )
