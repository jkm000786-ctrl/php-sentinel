import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.activation import (
    IntelligenceActivationError,
    activate_intelligence_with_lifecycle,
)
from php_sentinel.intelligence.lifecycle import (
    evaluate_lifecycle,
    load_lifecycle_state,
    save_lifecycle_state,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_sha256,
)
from php_sentinel.intelligence.state_key import (
    authority_state_key_path_for_state,
    load_authority_state_key,
)
from php_sentinel.intelligence.trust import (
    create_signed_manifest,
    verify_manifest,
)
from php_sentinel.models.intelligence_lifecycle import (
    IntelligenceLifecyclePolicy,
    LifecycleStateRecord,
    LifecycleStateStore,
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
    0,
    tzinfo=UTC,
)


def key_material():
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


def trusted_manifest(
    *,
    policy=None,
    generation=1,
    issued_at=NOW,
    expires_at=None,
    manifest_version=2,
    signer_id="lifecycle-signer",
):
    private_b64, public_b64 = key_material()

    selected = policy or default_policy().model_copy(deep=True)

    manifest = create_signed_manifest(
        policy=selected,
        signer_id=signer_id,
        private_key_b64=private_b64,
        issued_at=issued_at,
        generation=generation,
        expires_at=(expires_at if expires_at is not None else (issued_at + timedelta(days=30))),
        manifest_version=manifest_version,
    )

    store = TrustStore(
        signers=[
            TrustedSigner(
                signer_id=signer_id,
                public_key_b64=public_b64,
            )
        ]
    )

    trust = verify_manifest(
        selected,
        manifest,
        store,
    )

    assert trust.trusted is True

    return (
        selected,
        manifest,
        trust,
        store,
    )


def test_current_manifest_is_activatable():
    (
        policy,
        manifest,
        trust,
        _,
    ) = trusted_manifest()

    result = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        now=NOW,
    )

    assert result.activatable is True
    assert result.state.value == "current"
    assert result.generation == 1


def test_expired_manifest_is_denied():
    issued_at = NOW - timedelta(days=10)

    (
        policy,
        manifest,
        trust,
        _,
    ) = trusted_manifest(
        issued_at=issued_at,
        expires_at=(NOW - timedelta(seconds=1)),
    )

    result = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        now=NOW,
    )

    assert result.activatable is False
    assert result.state.value == "expired"


def test_stale_manifest_is_denied():
    issued_at = NOW - timedelta(days=31)

    (
        policy,
        manifest,
        trust,
        _,
    ) = trusted_manifest(
        issued_at=issued_at,
        expires_at=(NOW + timedelta(days=1)),
    )

    result = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        lifecycle_policy=(IntelligenceLifecyclePolicy(maximum_age_days=30)),
        now=NOW,
    )

    assert result.activatable is False
    assert result.state.value == "stale"


def test_future_issued_manifest_is_denied():
    issued_at = NOW + timedelta(minutes=10)

    (
        policy,
        manifest,
        trust,
        _,
    ) = trusted_manifest(
        issued_at=issued_at,
    )

    result = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        now=NOW,
    )

    assert result.activatable is False
    assert result.state.value == "future_issued"


def test_below_minimum_generation_is_denied():
    (
        policy,
        manifest,
        trust,
        _,
    ) = trusted_manifest(
        generation=2,
    )

    result = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        lifecycle_policy=(IntelligenceLifecyclePolicy(minimum_generation=3)),
        now=NOW,
    )

    assert result.activatable is False
    assert result.state.value == "below_minimum_generation"


def test_rollback_is_detected():
    (
        policy,
        manifest,
        trust,
        _,
    ) = trusted_manifest(
        generation=4,
    )

    state = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=5,
                    policy_sha256=(trust.policy_sha256),
                    signer_id=(trust.signer_id),
                    accepted_at=NOW,
                )
            )
        }
    )

    result = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        state=state,
        now=NOW,
    )

    assert result.activatable is False
    assert result.state.value == "rollback_detected"


def test_same_generation_different_digest_is_rejected():
    original = default_policy().model_copy(deep=True)

    changed = default_policy().model_copy(deep=True)

    changed.fixed_versions["8.5"] = "8.5.13"

    (
        policy,
        manifest,
        trust,
        _,
    ) = trusted_manifest(
        policy=changed,
        generation=7,
    )

    state = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=7,
                    policy_sha256=(policy_sha256(original)),
                    signer_id=(trust.signer_id),
                    accepted_at=NOW,
                )
            )
        }
    )

    result = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        state=state,
        now=NOW,
    )

    assert result.activatable is False
    assert result.state.value == "replay_detected"


def test_legacy_v1_manifest_verifies_but_is_not_activatable():
    (
        policy,
        manifest,
        trust,
        _,
    ) = trusted_manifest(
        manifest_version=1,
    )

    assert manifest.manifest_version == 1
    assert trust.trusted is True

    result = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        now=NOW,
    )

    assert result.activatable is False
    assert result.state.value == "legacy_no_lifecycle"


def test_persistent_state_blocks_rollback(
    tmp_path,
):
    private_b64, public_b64 = key_material()

    policy = default_policy().model_copy(deep=True)

    store = TrustStore(
        signers=[
            TrustedSigner(
                signer_id="state-signer",
                public_key_b64=public_b64,
            )
        ]
    )

    policy_path = tmp_path / "policy.json"
    trust_path = tmp_path / "trust.json"
    state_path = tmp_path / "lifecycle.json"

    policy_path.write_text(
        json.dumps(policy.model_dump(mode="json")),
        encoding="utf-8",
    )

    trust_path.write_text(
        json.dumps(store.model_dump(mode="json")),
        encoding="utf-8",
    )

    newer = create_signed_manifest(
        policy=policy,
        signer_id="state-signer",
        private_key_b64=private_b64,
        issued_at=NOW,
        generation=5,
        expires_at=(NOW + timedelta(days=10)),
    )

    newer_path = tmp_path / "newer.json"

    newer_path.write_text(
        json.dumps(newer.model_dump(mode="json")),
        encoding="utf-8",
    )

    (
        _,
        _,
        lifecycle,
    ) = activate_intelligence_with_lifecycle(
        policy_path=policy_path,
        manifest_path=newer_path,
        trust_store_path=trust_path,
        lifecycle_state_path=state_path,
        now=NOW,
    )

    assert lifecycle.activatable is True
    assert lifecycle.generation == 5

    authority_key_path = authority_state_key_path_for_state(state_path)
    authority_key = load_authority_state_key(authority_key_path)

    persisted = load_lifecycle_state(
        state_path,
        authority_key=authority_key,
        require_authenticated=True,
    )

    assert persisted.records[policy.policy_id].generation == 5

    older = create_signed_manifest(
        policy=policy,
        signer_id="state-signer",
        private_key_b64=private_b64,
        issued_at=NOW,
        generation=4,
        expires_at=(NOW + timedelta(days=10)),
    )

    older_path = tmp_path / "older.json"

    older_path.write_text(
        json.dumps(older.model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceActivationError,
        match="rollback_detected",
    ):
        activate_intelligence_with_lifecycle(
            policy_path=policy_path,
            manifest_path=older_path,
            trust_store_path=trust_path,
            lifecycle_state_path=state_path,
            now=NOW,
        )


def test_authoritative_activation_rejects_unsigned_legacy_state(
    tmp_path,
):
    private_b64, public_b64 = key_material()

    policy = default_policy().model_copy(deep=True)

    store = TrustStore(
        signers=[
            TrustedSigner(
                signer_id="state-signer",
                public_key_b64=public_b64,
            )
        ]
    )

    policy_path = tmp_path / "policy.json"
    manifest_path = tmp_path / "manifest.json"
    trust_path = tmp_path / "trust.json"
    state_path = tmp_path / "lifecycle.json"

    policy_path.write_text(
        json.dumps(policy.model_dump(mode="json")),
        encoding="utf-8",
    )

    trust_path.write_text(
        json.dumps(store.model_dump(mode="json")),
        encoding="utf-8",
    )

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="state-signer",
        private_key_b64=private_b64,
        issued_at=NOW,
        generation=5,
        expires_at=(NOW + timedelta(days=10)),
    )

    manifest_path.write_text(
        json.dumps(manifest.model_dump(mode="json")),
        encoding="utf-8",
    )

    save_lifecycle_state(
        state_path,
        LifecycleStateStore(),
    )

    with pytest.raises(
        IntelligenceActivationError,
        match="not an authenticated authority-state envelope",
    ):
        activate_intelligence_with_lifecycle(
            policy_path=policy_path,
            manifest_path=manifest_path,
            trust_store_path=trust_path,
            lifecycle_state_path=state_path,
            now=NOW,
        )
