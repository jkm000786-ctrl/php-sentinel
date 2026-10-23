import base64
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.delegation import (
    DELEGATION_REVOCATION_SIGNATURE_DOMAIN_V1,
    create_signed_delegation_revocation,
    create_signed_signer_delegation,
    delegation_is_revoked,
    revocation_signing_bytes,
    signer_delegation_revocation_sha256,
    signer_delegation_sha256,
    verify_delegation_revocation,
)
from php_sentinel.intelligence.lifecycle import (
    evaluate_lifecycle,
    load_lifecycle_state,
    record_accepted_lifecycle,
    record_observed_delegation_revocations,
    save_lifecycle_state,
)
from php_sentinel.intelligence.registry_trust import (
    create_signed_source_registry_manifest,
    evaluate_source_registry_lifecycle,
    load_source_registry_state,
    record_accepted_source_registry,
    record_observed_source_registry_revocations,
    save_source_registry_state,
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
    DelegationHistoryRecord,
    LifecycleStateRecord,
    LifecycleStateStore,
)
from php_sentinel.models.intelligence_source import (
    IntelligenceSourceRegistry,
)
from php_sentinel.models.intelligence_trust import (
    SignerDelegationRevocation,
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
    45,
    tzinfo=UTC,
)


def key_pair() -> tuple[str, str]:
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


def intelligence_rotation(
    *,
    sequence: int,
    generation: int = 6,
):
    old_private, old_public = key_pair()
    new_private, new_public = key_pair()

    policy = default_policy()

    delegation = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old",
        predecessor_private_key_b64=old_private,
        successor_signer_id="new",
        successor_public_key_b64=new_public,
        sequence=sequence,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="new",
        private_key_b64=new_private,
        generation=generation,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust_store = TrustStore(
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
    )

    trust = verify_manifest(
        policy,
        manifest,
        trust_store,
        now=NOW,
    )

    return (
        old_private,
        policy,
        manifest,
        delegation,
        trust_store,
        trust,
    )


def registry_rotation(
    *,
    sequence: int,
    generation: int = 6,
):
    old_private, old_public = key_pair()
    new_private, new_public = key_pair()

    registry = IntelligenceSourceRegistry()

    delegation = create_signed_signer_delegation(
        context="registry",
        predecessor_signer_id="old",
        predecessor_private_key_b64=old_private,
        successor_signer_id="new",
        successor_public_key_b64=new_public,
        sequence=sequence,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    manifest = create_signed_source_registry_manifest(
        registry=registry,
        signer_id="new",
        private_key_b64=new_private,
        generation=generation,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust_store = TrustStore(
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
    )

    trust = verify_source_registry_manifest(
        registry=registry,
        manifest=manifest,
        trust_store=trust_store,
        now=NOW,
    )

    return (
        old_private,
        registry,
        manifest,
        delegation,
        trust_store,
        trust,
    )


def test_revocation_uses_distinct_signature_domain():
    (
        old_private,
        _,
        _,
        delegation,
        _,
        _,
    ) = intelligence_rotation(sequence=1)

    revocation = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=(old_private),
        revocation_sequence=1,
        issued_at=NOW,
    )

    assert revocation_signing_bytes(revocation).startswith(
        DELEGATION_REVOCATION_SIGNATURE_DOMAIN_V1
    )


def test_valid_signed_revocation_blocks_exact_delegation():
    (
        old_private,
        _,
        _,
        delegation,
        trust_store,
        _,
    ) = intelligence_rotation(sequence=1)

    revocation = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=(old_private),
        revocation_sequence=1,
        issued_at=NOW,
    )

    store = trust_store.model_copy(update={"delegation_revocations": [revocation]})

    assert verify_delegation_revocation(
        revocation=revocation,
        delegation=delegation,
        trust_store=store,
        now=NOW,
    )

    assert delegation_is_revoked(
        delegation=delegation,
        trust_store=store,
        now=NOW,
    )


def test_revocation_is_bound_to_exact_delegation_digest():
    (
        old_private,
        _,
        _,
        delegation,
        trust_store,
        _,
    ) = intelligence_rotation(sequence=1)

    revocation = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=(old_private),
        revocation_sequence=1,
        issued_at=NOW,
    )

    data = revocation.model_dump(mode="python")

    data["delegation_sha256"] = "0" * 64

    tampered = SignerDelegationRevocation.model_validate(data)

    assert not verify_delegation_revocation(
        revocation=tampered,
        delegation=delegation,
        trust_store=trust_store,
        now=NOW,
    )


def test_intelligence_lower_historical_sequence_fails_closed():
    (
        _,
        policy,
        manifest,
        _,
        _,
        trust,
    ) = intelligence_rotation(sequence=1)

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
        },
        delegation_records={
            "intelligence|old|new": (
                DelegationHistoryRecord(
                    sequence=2,
                    delegation_sha256=("0" * 64),
                    accepted_at=NOW,
                )
            )
        },
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


def test_intelligence_same_sequence_different_digest_fails_closed():
    (
        _,
        policy,
        manifest,
        _,
        _,
        trust,
    ) = intelligence_rotation(sequence=2)

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
        },
        delegation_records={
            "intelligence|old|new": (
                DelegationHistoryRecord(
                    sequence=2,
                    delegation_sha256=("f" * 64),
                    accepted_at=NOW,
                )
            )
        },
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


def test_intelligence_higher_sequence_persists_atomically(
    tmp_path,
):
    (
        _,
        policy,
        manifest,
        delegation,
        _,
        trust,
    ) = intelligence_rotation(sequence=3)

    initial = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=5,
                    policy_sha256=(policy_sha256(policy)),
                    signer_id="old",
                    accepted_at=NOW,
                )
            )
        },
        delegation_records={
            "intelligence|old|new": (
                DelegationHistoryRecord(
                    sequence=2,
                    delegation_sha256=("0" * 64),
                    accepted_at=NOW,
                )
            )
        },
    )

    before = initial.model_dump(mode="json")

    decision = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        state=initial,
        now=NOW,
    )

    # Evaluation is read-only.
    assert initial.model_dump(mode="json") == before

    assert decision.activatable
    assert decision.rotation_delegation_sequence == 3

    state_path = tmp_path / "intelligence-state.json"

    save_lifecycle_state(
        state_path,
        initial,
    )

    record_accepted_lifecycle(
        path=state_path,
        policy=policy,
        lifecycle=decision,
        expected_state=initial,
        now=NOW,
    )

    recorded = load_lifecycle_state(state_path)

    history = recorded.delegation_records["intelligence|old|new"]

    assert history.sequence == 3
    assert history.delegation_sha256 == signer_delegation_sha256(delegation)

    assert recorded.records[policy.policy_id].generation == manifest.generation

    assert recorded.records[policy.policy_id].signer_id == "new"


def test_registry_lower_historical_sequence_fails_closed():
    (
        _,
        registry,
        manifest,
        _,
        _,
        trust,
    ) = registry_rotation(sequence=1)

    state = SourceRegistryStateStore(
        records={
            manifest.registry_id: (
                SourceRegistryStateRecord(
                    generation=5,
                    registry_sha256=(source_registry_sha256(registry)),
                    signer_id="old",
                    accepted_at=NOW,
                )
            )
        },
        delegation_records={
            "registry|old|new": (
                DelegationHistoryRecord(
                    sequence=2,
                    delegation_sha256=("0" * 64),
                    accepted_at=NOW,
                )
            )
        },
    )

    decision = evaluate_source_registry_lifecycle(
        registry=registry,
        manifest=manifest,
        trust=trust,
        state=state,
        now=NOW,
    )

    assert decision.activatable is False
    assert decision.state.value == "signer_changed"


def test_registry_same_sequence_different_digest_fails_closed():
    (
        _,
        registry,
        manifest,
        _,
        _,
        trust,
    ) = registry_rotation(sequence=2)

    state = SourceRegistryStateStore(
        records={
            manifest.registry_id: (
                SourceRegistryStateRecord(
                    generation=5,
                    registry_sha256=(source_registry_sha256(registry)),
                    signer_id="old",
                    accepted_at=NOW,
                )
            )
        },
        delegation_records={
            "registry|old|new": (
                DelegationHistoryRecord(
                    sequence=2,
                    delegation_sha256=("f" * 64),
                    accepted_at=NOW,
                )
            )
        },
    )

    decision = evaluate_source_registry_lifecycle(
        registry=registry,
        manifest=manifest,
        trust=trust,
        state=state,
        now=NOW,
    )

    assert decision.activatable is False
    assert decision.state.value == "signer_changed"


def test_registry_higher_sequence_persists_atomically(
    tmp_path,
):
    (
        _,
        registry,
        manifest,
        delegation,
        _,
        trust,
    ) = registry_rotation(sequence=3)

    initial = SourceRegistryStateStore(
        records={
            manifest.registry_id: (
                SourceRegistryStateRecord(
                    generation=5,
                    registry_sha256=(source_registry_sha256(registry)),
                    signer_id="old",
                    accepted_at=NOW,
                )
            )
        },
        delegation_records={
            "registry|old|new": (
                DelegationHistoryRecord(
                    sequence=2,
                    delegation_sha256=("0" * 64),
                    accepted_at=NOW,
                )
            )
        },
    )

    before = initial.model_dump(mode="json")

    decision = evaluate_source_registry_lifecycle(
        registry=registry,
        manifest=manifest,
        trust=trust,
        state=initial,
        now=NOW,
    )

    # Verification/evaluation does not mutate state.
    assert initial.model_dump(mode="json") == before

    assert decision.activatable
    assert decision.rotation_delegation_sequence == 3

    state_path = tmp_path / "registry-state.json"

    save_source_registry_state(
        state_path,
        initial,
    )

    record_accepted_source_registry(
        path=state_path,
        registry=registry,
        manifest=manifest,
        lifecycle=decision,
        expected_state=initial,
        now=NOW,
    )

    recorded = load_source_registry_state(state_path)

    history = recorded.delegation_records["registry|old|new"]

    assert history.sequence == 3
    assert history.delegation_sha256 == signer_delegation_sha256(delegation)

    assert recorded.records[manifest.registry_id].generation == manifest.generation

    assert recorded.records[manifest.registry_id].signer_id == "new"


def test_intelligence_and_registry_history_are_context_separated():
    intelligence = LifecycleStateStore(
        delegation_records={
            "intelligence|old|new": (
                DelegationHistoryRecord(
                    sequence=7,
                    delegation_sha256=("a" * 64),
                    accepted_at=NOW,
                )
            )
        }
    )

    registry = SourceRegistryStateStore(
        delegation_records={
            "registry|old|new": (
                DelegationHistoryRecord(
                    sequence=4,
                    delegation_sha256=("b" * 64),
                    accepted_at=NOW,
                )
            )
        }
    )

    assert "registry|old|new" not in intelligence.delegation_records

    assert "intelligence|old|new" not in registry.delegation_records


def test_intelligence_revocation_history_survives_revocation_removal(
    tmp_path,
):
    (
        old_private,
        policy,
        manifest,
        delegation,
        trust_store,
        _,
    ) = intelligence_rotation(sequence=3)

    revocation = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=old_private,
        revocation_sequence=2,
        issued_at=NOW,
    )

    state_path = tmp_path / "intelligence-state.json"

    initial = LifecycleStateStore(
        records={
            policy.policy_id: LifecycleStateRecord(
                generation=5,
                policy_sha256=policy_sha256(policy),
                signer_id="old",
                accepted_at=NOW,
            )
        }
    )

    save_lifecycle_state(
        state_path,
        initial,
    )

    recorded = record_observed_delegation_revocations(
        path=state_path,
        revocations=[revocation],
        expected_state=initial,
        now=NOW,
    )

    key = "intelligence|old|new|3|" + signer_delegation_sha256(delegation)

    assert recorded.revocation_records[key].revocation_sequence == 2
    assert recorded.revocation_records[
        key
    ].revocation_sha256 == signer_delegation_revocation_sha256(revocation)

    # Current TrustStore no longer carries the revocation.
    trust_without_revocation = verify_manifest(
        policy,
        manifest,
        trust_store,
        now=NOW,
    )

    assert "old" in (trust_without_revocation.authorized_predecessor_signer_ids)

    decision = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust_without_revocation,
        state=recorded,
        now=NOW,
    )

    assert decision.activatable is False
    assert decision.state.value == "signer_changed"


def test_registry_revocation_history_survives_revocation_removal(
    tmp_path,
):
    (
        old_private,
        registry,
        manifest,
        delegation,
        trust_store,
        _,
    ) = registry_rotation(sequence=3)

    revocation = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=old_private,
        revocation_sequence=4,
        issued_at=NOW,
    )

    state_path = tmp_path / "registry-state.json"

    initial = SourceRegistryStateStore(
        records={
            manifest.registry_id: SourceRegistryStateRecord(
                generation=5,
                registry_sha256=source_registry_sha256(registry),
                signer_id="old",
                accepted_at=NOW,
            )
        }
    )

    save_source_registry_state(
        state_path,
        initial,
    )

    recorded = record_observed_source_registry_revocations(
        path=state_path,
        revocations=[revocation],
        expected_state=initial,
        now=NOW,
    )

    key = "registry|old|new|3|" + signer_delegation_sha256(delegation)

    assert recorded.revocation_records[key].revocation_sequence == 4
    assert recorded.revocation_records[
        key
    ].revocation_sha256 == signer_delegation_revocation_sha256(revocation)

    # Current TrustStore no longer carries the revocation.
    trust_without_revocation = verify_source_registry_manifest(
        registry=registry,
        manifest=manifest,
        trust_store=trust_store,
        now=NOW,
    )

    assert "old" in (trust_without_revocation.authorized_predecessor_signer_ids)

    decision = evaluate_source_registry_lifecycle(
        registry=registry,
        manifest=manifest,
        trust=trust_without_revocation,
        state=recorded,
        now=NOW,
    )

    assert decision.activatable is False
    assert decision.state.value == "signer_changed"


def test_intelligence_revocation_history_rejects_sequence_rollback(
    tmp_path,
):
    (
        old_private,
        _,
        _,
        delegation,
        _,
        _,
    ) = intelligence_rotation(sequence=2)

    high = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=old_private,
        revocation_sequence=5,
        issued_at=NOW,
    )

    low = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=old_private,
        revocation_sequence=4,
        issued_at=NOW,
    )

    path = tmp_path / "state.json"

    initial = LifecycleStateStore()

    save_lifecycle_state(
        path,
        initial,
    )

    recorded = record_observed_delegation_revocations(
        path=path,
        revocations=[high],
        expected_state=initial,
        now=NOW,
    )

    import pytest

    from php_sentinel.intelligence.lifecycle import (
        LifecycleStateStorageError,
    )

    with pytest.raises(
        LifecycleStateStorageError,
        match="older delegation revocation sequence",
    ):
        record_observed_delegation_revocations(
            path=path,
            revocations=[low],
            expected_state=recorded,
            now=NOW,
        )


def test_registry_revocation_history_rejects_sequence_rollback(
    tmp_path,
):
    (
        old_private,
        _,
        _,
        delegation,
        _,
        _,
    ) = registry_rotation(sequence=2)

    high = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=old_private,
        revocation_sequence=7,
        issued_at=NOW,
    )

    low = create_signed_delegation_revocation(
        delegation=delegation,
        predecessor_private_key_b64=old_private,
        revocation_sequence=6,
        issued_at=NOW,
    )

    path = tmp_path / "registry-state.json"

    initial = SourceRegistryStateStore()

    save_source_registry_state(
        path,
        initial,
    )

    recorded = record_observed_source_registry_revocations(
        path=path,
        revocations=[high],
        expected_state=initial,
        now=NOW,
    )

    import pytest

    from php_sentinel.intelligence.registry_trust import (
        SourceRegistryStateStorageError,
    )

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="older registry delegation revocation sequence",
    ):
        record_observed_source_registry_revocations(
            path=path,
            revocations=[low],
            expected_state=recorded,
            now=NOW,
        )


def test_revocation_history_contexts_remain_separate():
    intelligence = LifecycleStateStore()
    registry = SourceRegistryStateStore()

    assert intelligence.revocation_records == {}
    assert registry.revocation_records == {}
