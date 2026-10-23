import base64
import json

import pytest
from cryptography.hazmat.primitives import (
    serialization,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.activation import (
    IntelligenceActivationError,
    activate_intelligence,
)
from php_sentinel.intelligence.repository import (
    default_policy,
)
from php_sentinel.intelligence.trust import (
    create_signed_manifest,
)
from php_sentinel.models.intelligence_trust import (
    TrustedSigner,
    TrustStore,
)


def signing_material():
    private_key = Ed25519PrivateKey.generate()

    private_raw = private_key.private_bytes(
        encoding=(serialization.Encoding.Raw),
        format=(serialization.PrivateFormat.Raw),
        encryption_algorithm=(serialization.NoEncryption()),
    )

    public_raw = private_key.public_key().public_bytes(
        encoding=(serialization.Encoding.Raw),
        format=(serialization.PublicFormat.Raw),
    )

    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def write_verified_bundle(
    tmp_path,
):
    private_b64, public_b64 = signing_material()

    policy = default_policy().model_copy(deep=True)

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="phase14-test-signer",
        private_key_b64=private_b64,
    )

    trust_store = TrustStore(
        signers=[
            TrustedSigner(
                signer_id=("phase14-test-signer"),
                public_key_b64=public_b64,
            )
        ]
    )

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
        json.dumps(trust_store.model_dump(mode="json")),
        encoding="utf-8",
    )

    return (
        policy,
        policy_path,
        manifest_path,
        trust_path,
    )


def test_default_activation_uses_bundled_policy():
    policy, trust = activate_intelligence()

    assert policy.policy_id == "php-2026-10-critical"

    assert trust.trusted is True
    assert trust.state.value == "bundled_trusted"

    assert trust.signer_id == "php-sentinel-package"


@pytest.mark.parametrize(
    (
        "policy_path",
        "manifest_path",
        "trust_store_path",
    ),
    [
        ("policy.json", None, None),
        (
            None,
            "manifest.json",
            None,
        ),
        (
            None,
            None,
            "trust.json",
        ),
        (
            "policy.json",
            "manifest.json",
            None,
        ),
        (
            "policy.json",
            None,
            "trust.json",
        ),
        (
            None,
            "manifest.json",
            "trust.json",
        ),
    ],
)
def test_partial_external_activation_is_denied(
    policy_path,
    manifest_path,
    trust_store_path,
):
    with pytest.raises(
        IntelligenceActivationError,
        match="requires --policy",
    ):
        activate_intelligence(
            policy_path=policy_path,
            manifest_path=manifest_path,
            trust_store_path=(trust_store_path),
        )


def test_verified_external_policy_is_activated(
    tmp_path,
):
    (
        expected_policy,
        policy_path,
        manifest_path,
        trust_path,
    ) = write_verified_bundle(tmp_path)

    policy, trust = activate_intelligence(
        policy_path=policy_path,
        manifest_path=manifest_path,
        trust_store_path=trust_path,
    )

    assert policy.policy_id == expected_policy.policy_id

    assert trust.trusted is True
    assert trust.state.value == "trusted"
    assert trust.signer_id == "phase14-test-signer"


def test_external_policy_unknown_signer_fails_closed(
    tmp_path,
):
    (
        _,
        policy_path,
        manifest_path,
        trust_path,
    ) = write_verified_bundle(tmp_path)

    trust_path.write_text(
        json.dumps(TrustStore().model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceActivationError,
        match="unknown_signer",
    ):
        activate_intelligence(
            policy_path=policy_path,
            manifest_path=manifest_path,
            trust_store_path=trust_path,
        )
