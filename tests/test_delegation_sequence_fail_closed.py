import base64
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.delegation import (
    create_signed_delegation_revocation,
    create_signed_signer_delegation,
    resolve_authorized_predecessor_evidence,
)
from php_sentinel.models.intelligence_trust import (
    TrustedSigner,
    TrustStore,
)

NOW = datetime(
    2026,
    10,
    23,
    18,
    30,
    tzinfo=UTC,
)


def key_pair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()

    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=(serialization.NoEncryption()),
    )

    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def build_store_with_two_delegations(
    *,
    context: str = "intelligence",
    high_expires_at: datetime | None = None,
):
    old_private, old_public = key_pair()
    _, new_public = key_pair()

    low = create_signed_signer_delegation(
        context=context,
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        sequence=1,
        minimum_successor_generation=2,
        issued_at=(NOW - timedelta(days=2)),
        expires_at=(NOW + timedelta(days=10)),
    )

    high = create_signed_signer_delegation(
        context=context,
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        sequence=2,
        minimum_successor_generation=3,
        issued_at=(NOW - timedelta(days=1)),
        expires_at=(high_expires_at or (NOW + timedelta(days=10))),
    )

    signers = [
        TrustedSigner(
            signer_id="old",
            public_key_b64=old_public,
        ),
        TrustedSigner(
            signer_id="new",
            public_key_b64=new_public,
        ),
    ]

    return (
        old_private,
        new_public,
        low,
        high,
        signers,
    )


def test_highest_sequence_is_selected_when_valid():
    (
        _,
        new_public,
        low,
        high,
        signers,
    ) = build_store_with_two_delegations()

    evidence = resolve_authorized_predecessor_evidence(
        trust_store=TrustStore(
            signers=signers,
            delegations=[
                low,
                high,
            ],
        ),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        context="intelligence",
        now=NOW,
    )

    assert evidence["old"].sequence == 2


def test_revoked_highest_sequence_blocks_lower_fallback():
    (
        old_private,
        new_public,
        low,
        high,
        signers,
    ) = build_store_with_two_delegations()

    revocation = create_signed_delegation_revocation(
        delegation=high,
        predecessor_private_key_b64=(old_private),
        revocation_sequence=1,
        issued_at=NOW,
    )

    evidence = resolve_authorized_predecessor_evidence(
        trust_store=TrustStore(
            signers=signers,
            delegations=[
                low,
                high,
            ],
            delegation_revocations=[revocation],
        ),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        context="intelligence",
        now=NOW,
    )

    assert evidence == {}


def test_expired_highest_sequence_blocks_lower_fallback():
    (
        _,
        new_public,
        low,
        high,
        signers,
    ) = build_store_with_two_delegations(high_expires_at=(NOW - timedelta(seconds=1)))

    evidence = resolve_authorized_predecessor_evidence(
        trust_store=TrustStore(
            signers=signers,
            delegations=[
                low,
                high,
            ],
        ),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        context="intelligence",
        now=NOW,
    )

    assert evidence == {}


def test_registry_context_obeys_same_no_fallback_rule():
    (
        old_private,
        new_public,
        low,
        high,
        signers,
    ) = build_store_with_two_delegations(context="registry")

    revocation = create_signed_delegation_revocation(
        delegation=high,
        predecessor_private_key_b64=(old_private),
        revocation_sequence=1,
        issued_at=NOW,
    )

    evidence = resolve_authorized_predecessor_evidence(
        trust_store=TrustStore(
            signers=signers,
            delegations=[
                low,
                high,
            ],
            delegation_revocations=[revocation],
        ),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        context="registry",
        now=NOW,
    )

    assert evidence == {}
