import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.repository import (
    default_policy,
)
from php_sentinel.intelligence.trust import (
    create_signed_manifest,
    load_verified_external_policy,
    verify_manifest,
)
from php_sentinel.models.intelligence_trust import (
    TrustedSigner,
    TrustStore,
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


def trusted_fixture():
    private_b64, public_b64 = key_material()

    policy = default_policy().model_copy(deep=True)

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="test-signer",
        private_key_b64=private_b64,
    )

    store = TrustStore(
        signers=[
            TrustedSigner(
                signer_id="test-signer",
                public_key_b64=public_b64,
            )
        ]
    )

    return policy, manifest, store


def test_valid_signature_is_trusted():
    policy, manifest, store = trusted_fixture()

    result = verify_manifest(
        policy,
        manifest,
        store,
    )

    assert result.trusted is True
    assert result.state.value == "trusted"
    assert result.signer_id == "test-signer"


def test_policy_tampering_causes_digest_mismatch():
    policy, manifest, store = trusted_fixture()

    policy.fixed_versions["8.5"] = "8.5.13"

    result = verify_manifest(
        policy,
        manifest,
        store,
    )

    assert result.trusted is False
    assert result.state.value == "digest_mismatch"


def test_unknown_signer_is_not_trusted():
    policy, manifest, _ = trusted_fixture()

    result = verify_manifest(
        policy,
        manifest,
        TrustStore(),
    )

    assert result.trusted is False
    assert result.state.value == "unknown_signer"


def test_invalid_signature_is_rejected():
    policy, manifest, store = trusted_fixture()

    raw = bytearray(base64.b64decode(manifest.signature_b64))

    raw[0] ^= 1

    manifest = manifest.model_copy(
        update={"signature_b64": (base64.b64encode(bytes(raw)).decode("ascii"))}
    )

    result = verify_manifest(
        policy,
        manifest,
        store,
    )

    assert result.trusted is False
    assert result.state.value == "invalid_signature"


def test_verified_external_policy_loader(
    tmp_path,
):
    policy, manifest, store = trusted_fixture()

    policy_path = tmp_path / "policy.json"
    manifest_path = tmp_path / "manifest.json"
    trust_path = tmp_path / "trust.json"

    policy_path.write_text(
        json.dumps(policy.model_dump(mode="json")),
        encoding="utf-8",
    )

    manifest_path.write_text(
        json.dumps(manifest.model_dump(mode="json")),
        encoding="utf-8",
    )

    trust_path.write_text(
        json.dumps(store.model_dump(mode="json")),
        encoding="utf-8",
    )

    loaded, decision = load_verified_external_policy(
        policy_path=policy_path,
        manifest_path=manifest_path,
        trust_store_path=trust_path,
    )

    assert loaded.policy_id == policy.policy_id
    assert decision.trusted is True


def test_external_policy_loader_fails_closed(
    tmp_path,
):
    policy, manifest, _ = trusted_fixture()

    policy_path = tmp_path / "policy.json"
    manifest_path = tmp_path / "manifest.json"
    trust_path = tmp_path / "trust.json"

    policy_path.write_text(
        json.dumps(policy.model_dump(mode="json")),
        encoding="utf-8",
    )

    manifest_path.write_text(
        json.dumps(manifest.model_dump(mode="json")),
        encoding="utf-8",
    )

    trust_path.write_text(
        json.dumps(TrustStore().model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="trust verification failed",
    ):
        load_verified_external_policy(
            policy_path=policy_path,
            manifest_path=manifest_path,
            trust_store_path=trust_path,
        )
