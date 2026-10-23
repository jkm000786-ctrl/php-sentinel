from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from php_sentinel.models.intelligence_trust import (
    SignerDelegation,
    SignerDelegationRevocation,
    TrustStore,
    VerifiedSignerDelegationEvidence,
)

DELEGATION_SIGNATURE_DOMAIN_V1 = b"PHP-SENTINEL-SIGNER-DELEGATION-V1\x00"

DELEGATION_REVOCATION_SIGNATURE_DOMAIN_V1 = b"PHP-SENTINEL-SIGNER-DELEGATION-REVOCATION-V1\x00"

ED25519_PRIVATE_KEY_BYTES = 32
ED25519_PUBLIC_KEY_BYTES = 32


def delegation_signing_payload(
    delegation: SignerDelegation,
) -> dict[str, object]:
    return {
        "delegation_version": delegation.delegation_version,
        "context": delegation.context,
        "predecessor_signer_id": delegation.predecessor_signer_id,
        "successor_signer_id": delegation.successor_signer_id,
        "successor_public_key_b64": delegation.successor_public_key_b64,
        "sequence": delegation.sequence,
        "minimum_successor_generation": (delegation.minimum_successor_generation),
        "issued_at": delegation.issued_at.isoformat(),
        "expires_at": delegation.expires_at.isoformat(),
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


def signer_delegation_sha256(
    delegation: SignerDelegation,
) -> str:
    signature = base64.b64decode(
        delegation.signature_b64,
        validate=True,
    )

    payload = delegation_signing_bytes(delegation) + b"\x00" + signature

    return hashlib.sha256(payload).hexdigest()


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


def revocation_signing_payload(
    revocation: SignerDelegationRevocation,
) -> dict[str, object]:
    return {
        "revocation_version": revocation.revocation_version,
        "context": revocation.context,
        "predecessor_signer_id": (revocation.predecessor_signer_id),
        "successor_signer_id": (revocation.successor_signer_id),
        "delegation_sequence": (revocation.delegation_sequence),
        "delegation_sha256": (revocation.delegation_sha256),
        "revocation_sequence": (revocation.revocation_sequence),
        "issued_at": (revocation.issued_at.isoformat()),
        "algorithm": revocation.algorithm,
    }


def revocation_signing_bytes(
    revocation: SignerDelegationRevocation,
) -> bytes:
    canonical = json.dumps(
        revocation_signing_payload(revocation),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return DELEGATION_REVOCATION_SIGNATURE_DOMAIN_V1 + canonical


def create_signed_delegation_revocation(
    *,
    delegation: SignerDelegation,
    predecessor_private_key_b64: str,
    revocation_sequence: int,
    issued_at: datetime | None = None,
) -> SignerDelegationRevocation:
    private_bytes = base64.b64decode(
        predecessor_private_key_b64,
        validate=True,
    )

    if len(private_bytes) != ED25519_PRIVATE_KEY_BYTES:
        raise ValueError("Delegation revocation private key must decode to exactly 32 bytes.")

    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

    placeholder = base64.b64encode(b"\x00" * 64).decode("ascii")

    revocation = SignerDelegationRevocation(
        context=delegation.context,
        predecessor_signer_id=(delegation.predecessor_signer_id),
        successor_signer_id=(delegation.successor_signer_id),
        delegation_sequence=(delegation.sequence),
        delegation_sha256=(signer_delegation_sha256(delegation)),
        revocation_sequence=(revocation_sequence),
        issued_at=(issued_at or datetime.now(UTC)),
        algorithm="ed25519",
        signature_b64=placeholder,
    )

    signature = private_key.sign(revocation_signing_bytes(revocation))

    return revocation.model_copy(
        update={"signature_b64": (base64.b64encode(signature).decode("ascii"))}
    )


def verify_delegation_revocation(
    *,
    revocation: SignerDelegationRevocation,
    delegation: SignerDelegation,
    trust_store: TrustStore,
    now: datetime | None = None,
) -> bool:
    current_time = now or datetime.now(UTC)

    if (
        revocation.context != delegation.context
        or revocation.predecessor_signer_id != delegation.predecessor_signer_id
        or revocation.successor_signer_id != delegation.successor_signer_id
        or revocation.delegation_sequence != delegation.sequence
        or revocation.delegation_sha256 != signer_delegation_sha256(delegation)
    ):
        return False

    if revocation.algorithm != "ed25519":
        return False

    if revocation.issued_at > current_time:
        return False

    predecessor = next(
        (
            item
            for item in trust_store.signers
            if (item.signer_id == revocation.predecessor_signer_id and item.enabled)
        ),
        None,
    )

    if predecessor is None:
        return False

    try:
        public_bytes = base64.b64decode(
            predecessor.public_key_b64,
            validate=True,
        )

        if len(public_bytes) != ED25519_PUBLIC_KEY_BYTES:
            return False

        signature = base64.b64decode(
            revocation.signature_b64,
            validate=True,
        )

        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

        public_key.verify(
            signature,
            revocation_signing_bytes(revocation),
        )

    except (
        ValueError,
        InvalidSignature,
    ):
        return False

    return True


def delegation_is_revoked(
    *,
    delegation: SignerDelegation,
    trust_store: TrustStore,
    now: datetime | None = None,
) -> bool:
    return any(
        verify_delegation_revocation(
            revocation=item,
            delegation=delegation,
            trust_store=trust_store,
            now=now,
        )
        for item in trust_store.delegation_revocations
        if (
            item.context == delegation.context
            and item.predecessor_signer_id == delegation.predecessor_signer_id
            and item.successor_signer_id == delegation.successor_signer_id
            and item.delegation_sequence == delegation.sequence
        )
    )


def resolve_authorized_predecessor_evidence(
    *,
    trust_store: TrustStore,
    successor_signer_id: str,
    successor_public_key_b64: str,
    context: str,
    now: datetime | None = None,
) -> dict[
    str,
    VerifiedSignerDelegationEvidence,
]:
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

    evidence: dict[
        str,
        VerifiedSignerDelegationEvidence,
    ] = {}

    for predecessor_id, items in grouped.items():
        # Security invariant:
        #
        # Select the highest sequence FIRST. A revoked, expired,
        # malformed, or otherwise invalid highest-sequence delegation
        # MUST block authorization for this predecessor. Never fall
        # back to an older still-valid sequence.
        selected = max(
            items,
            key=lambda item: item.sequence,
        )

        if not verify_signer_delegation(
            delegation=selected,
            trust_store=trust_store,
            expected_context=context,
            successor_signer_id=(successor_signer_id),
            successor_public_key_b64=(successor_public_key_b64),
            now=now,
        ):
            continue

        if delegation_is_revoked(
            delegation=selected,
            trust_store=trust_store,
            now=now,
        ):
            continue

        evidence[predecessor_id] = VerifiedSignerDelegationEvidence(
            predecessor_signer_id=(predecessor_id),
            successor_signer_id=(successor_signer_id),
            sequence=selected.sequence,
            minimum_successor_generation=(selected.minimum_successor_generation),
            delegation_sha256=(signer_delegation_sha256(selected)),
        )

    return evidence


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
    Compatibility projection over the richer delegation-evidence API.
    """

    evidence = resolve_authorized_predecessor_evidence(
        trust_store=trust_store,
        successor_signer_id=(successor_signer_id),
        successor_public_key_b64=(successor_public_key_b64),
        context=context,
        now=now,
    )

    return (
        sorted(evidence),
        {
            predecessor_id: (item.minimum_successor_generation)
            for predecessor_id, item in evidence.items()
        },
    )
