import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.delegation import (
    DELEGATION_SIGNATURE_DOMAIN_V1,
    create_signed_signer_delegation,
    delegation_signing_bytes,
    resolve_authorized_predecessors,
)
from php_sentinel.intelligence.lifecycle import (
    evaluate_lifecycle,
)
from php_sentinel.intelligence.registry_trust import (
    create_signed_source_registry_manifest,
    evaluate_source_registry_lifecycle,
    source_registry_sha256,
    verify_source_registry_manifest,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_sha256,
)
from php_sentinel.intelligence.trust import (
    create_signed_manifest,
    verify_manifest,
)
from php_sentinel.models.intelligence_lifecycle import (
    LifecycleStateRecord,
    LifecycleStateStore,
)
from php_sentinel.models.intelligence_source import (
    IntelligenceSourceRegistry,
)
from php_sentinel.models.intelligence_trust import (
    TrustedSigner,
    TrustStore,
)
from php_sentinel.models.registry_trust import (
    SourceRegistryStateRecord,
    SourceRegistryStateStore,
)

NOW = datetime(
    2026,
    10,
    23,
    18,
    0,
    tzinfo=UTC,
)


def key_pair():
    private = Ed25519PrivateKey.generate()

    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=(serialization.NoEncryption()),
    )

    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def test_delegation_signature_is_domain_separated():
    old_private, _ = key_pair()
    _, new_public = key_pair()

    delegation = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        sequence=1,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    assert delegation_signing_bytes(delegation).startswith(DELEGATION_SIGNATURE_DOMAIN_V1)


def test_self_delegation_is_rejected():
    private, public = key_pair()

    with pytest.raises(
        ValueError,
        match="cannot delegate rotation to itself",
    ):
        create_signed_signer_delegation(
            context="intelligence",
            predecessor_signer_id="same",
            predecessor_private_key_b64=private,
            successor_signer_id="same",
            successor_public_key_b64=public,
            sequence=1,
            minimum_successor_generation=2,
            issued_at=NOW,
            expires_at=(NOW + timedelta(days=1)),
        )


def test_valid_intelligence_delegation_authorizes_rotation():
    old_private, old_public = key_pair()
    new_private, new_public = key_pair()

    policy = default_policy()

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="new",
        private_key_b64=new_private,
        generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    delegation = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        sequence=1,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust = verify_manifest(
        policy,
        manifest,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old",
                    public_key_b64=old_public,
                ),
                TrustedSigner(
                    signer_id="new",
                    public_key_b64=new_public,
                ),
            ],
            delegations=[delegation],
        ),
        now=NOW,
    )

    state = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=5,
                    policy_sha256=(policy_sha256(policy)),
                    signer_id="old",
                    accepted_at=NOW,
                )
            )
        }
    )

    decision = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        state=state,
        now=NOW,
    )

    assert decision.activatable is True


def test_legacy_authorized_predecessor_metadata_is_not_authority():
    _, old_public = key_pair()
    new_private, new_public = key_pair()

    policy = default_policy()

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="new",
        private_key_b64=new_private,
        generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust = verify_manifest(
        policy,
        manifest,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old",
                    public_key_b64=old_public,
                ),
                TrustedSigner(
                    signer_id="new",
                    public_key_b64=new_public,
                    authorized_predecessors=["old"],
                ),
            ]
        ),
        now=NOW,
    )

    assert trust.authorized_predecessor_signer_ids == []


def test_wrong_successor_public_key_fails_closed():
    old_private, old_public = key_pair()
    _, new_public = key_pair()
    _, wrong_public = key_pair()

    delegation = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(wrong_public),
        sequence=1,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    authorized, _ = resolve_authorized_predecessors(
        trust_store=TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old",
                    public_key_b64=(old_public),
                ),
                TrustedSigner(
                    signer_id="new",
                    public_key_b64=(new_public),
                ),
            ],
            delegations=[delegation],
        ),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        context="intelligence",
        now=NOW,
    )

    assert authorized == []


def test_expired_delegation_fails_closed():
    old_private, old_public = key_pair()
    _, new_public = key_pair()

    delegation = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        sequence=1,
        minimum_successor_generation=6,
        issued_at=(NOW - timedelta(days=10)),
        expires_at=(NOW - timedelta(days=1)),
    )

    authorized, _ = resolve_authorized_predecessors(
        trust_store=TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old",
                    public_key_b64=old_public,
                ),
                TrustedSigner(
                    signer_id="new",
                    public_key_b64=new_public,
                ),
            ],
            delegations=[delegation],
        ),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        context="intelligence",
        now=NOW,
    )

    assert authorized == []


def test_delegated_minimum_generation_is_enforced():
    old_private, old_public = key_pair()
    new_private, new_public = key_pair()

    policy = default_policy()

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="new",
        private_key_b64=new_private,
        generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    delegation = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        sequence=1,
        minimum_successor_generation=7,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust = verify_manifest(
        policy,
        manifest,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old",
                    public_key_b64=old_public,
                ),
                TrustedSigner(
                    signer_id="new",
                    public_key_b64=new_public,
                ),
            ],
            delegations=[delegation],
        ),
        now=NOW,
    )

    state = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=5,
                    policy_sha256=(policy_sha256(policy)),
                    signer_id="old",
                    accepted_at=NOW,
                )
            )
        }
    )

    decision = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        state=state,
        now=NOW,
    )

    assert decision.activatable is False
    assert decision.state.value == "signer_changed"


def test_intelligence_delegation_cannot_authorize_registry_rotation():
    old_private, old_public = key_pair()
    new_private, new_public = key_pair()

    source_registry = IntelligenceSourceRegistry()

    manifest = create_signed_source_registry_manifest(
        registry=source_registry,
        signer_id="new",
        private_key_b64=new_private,
        generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    delegation = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        sequence=1,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust = verify_source_registry_manifest(
        registry=source_registry,
        manifest=manifest,
        trust_store=TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old",
                    public_key_b64=old_public,
                ),
                TrustedSigner(
                    signer_id="new",
                    public_key_b64=new_public,
                ),
            ],
            delegations=[delegation],
        ),
        now=NOW,
    )

    assert trust.authorized_predecessor_signer_ids == []


def test_valid_registry_delegation_authorizes_registry_rotation():
    old_private, old_public = key_pair()
    new_private, new_public = key_pair()

    source_registry = IntelligenceSourceRegistry()

    manifest = create_signed_source_registry_manifest(
        registry=source_registry,
        signer_id="new",
        private_key_b64=new_private,
        generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    delegation = create_signed_signer_delegation(
        context="registry",
        predecessor_signer_id="old",
        predecessor_private_key_b64=(old_private),
        successor_signer_id="new",
        successor_public_key_b64=(new_public),
        sequence=1,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust = verify_source_registry_manifest(
        registry=source_registry,
        manifest=manifest,
        trust_store=TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old",
                    public_key_b64=old_public,
                ),
                TrustedSigner(
                    signer_id="new",
                    public_key_b64=new_public,
                ),
            ],
            delegations=[delegation],
        ),
        now=NOW,
    )

    state = SourceRegistryStateStore(
        records={
            manifest.registry_id: (
                SourceRegistryStateRecord(
                    generation=5,
                    registry_sha256=(source_registry_sha256(source_registry)),
                    signer_id="old",
                    accepted_at=NOW,
                )
            )
        }
    )

    decision = evaluate_source_registry_lifecycle(
        registry=source_registry,
        manifest=manifest,
        trust=trust,
        state=state,
        now=NOW,
    )

    assert decision.activatable is True


def test_duplicate_delegation_identity_is_rejected():
    old_private, old_public = key_pair()
    _, new_public = key_pair()

    first = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old",
        predecessor_private_key_b64=old_private,
        successor_signer_id="new",
        successor_public_key_b64=new_public,
        sequence=1,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    second = first.model_copy()

    with pytest.raises(
        ValueError,
        match="identity tuples",
    ):
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old",
                    public_key_b64=old_public,
                ),
                TrustedSigner(
                    signer_id="new",
                    public_key_b64=new_public,
                ),
            ],
            delegations=[
                first,
                second,
            ],
        )
