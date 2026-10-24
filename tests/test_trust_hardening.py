import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.activation import (
    VerifiedIntelligenceSelection,
)
from php_sentinel.intelligence.delegation import (
    create_signed_signer_delegation,
)
from php_sentinel.intelligence.lifecycle import (
    bundled_lifecycle,
    evaluate_lifecycle,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_sha256,
)
from php_sentinel.intelligence.trust import (
    MANIFEST_SIGNATURE_DOMAIN_V3,
    create_signed_manifest,
    load_trust_store,
    manifest_signing_bytes,
    resolve_policy_trust,
    verify_manifest,
)
from php_sentinel.models.intelligence_lifecycle import (
    LifecycleStateRecord,
    LifecycleStateStore,
)
from php_sentinel.models.intelligence_trust import (
    IntelligenceManifest,
    IntelligenceTrustDecision,
    IntelligenceTrustState,
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


def key_pair() -> tuple[str, str]:
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


def test_v3_manifest_is_domain_separated():
    private_b64, _ = key_pair()

    manifest = create_signed_manifest(
        policy=default_policy(),
        signer_id="phase16",
        private_key_b64=private_b64,
        issued_at=NOW,
        generation=1,
        expires_at=(NOW + timedelta(days=1)),
    )

    assert manifest.manifest_version == 3

    assert manifest_signing_bytes(manifest).startswith(MANIFEST_SIGNATURE_DOMAIN_V3)


def test_v2_manifest_remains_verifiable():
    private_b64, public_b64 = key_pair()

    policy = default_policy()

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="legacy",
        private_key_b64=private_b64,
        issued_at=NOW,
        generation=1,
        expires_at=(NOW + timedelta(days=1)),
        manifest_version=2,
    )

    decision = verify_manifest(
        policy,
        manifest,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="legacy",
                    public_key_b64=(public_b64),
                )
            ]
        ),
    )

    assert decision.trusted is True


def test_unknown_trust_store_version_fails_closed():
    with pytest.raises(
        ValueError,
        match="Unsupported trust-store version",
    ):
        TrustStore.model_validate(
            {
                "store_version": 999,
                "signers": [],
            }
        )


def test_public_key_length_is_strict():
    with pytest.raises(
        ValueError,
        match="exactly 32 bytes",
    ):
        TrustedSigner(
            signer_id="bad",
            public_key_b64=(base64.b64encode(b"x" * 31).decode("ascii")),
        )


def test_signature_length_is_strict():
    private_b64, _ = key_pair()

    manifest = create_signed_manifest(
        policy=default_policy(),
        signer_id="signature",
        private_key_b64=private_b64,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=1)),
    )

    data = manifest.model_dump(mode="json")

    data["signature_b64"] = base64.b64encode(b"x" * 63).decode("ascii")

    with pytest.raises(
        ValueError,
        match="exactly 64 bytes",
    ):
        IntelligenceManifest.model_validate(data)


def test_private_key_length_is_strict():
    with pytest.raises(
        ValueError,
        match="exactly 32 bytes",
    ):
        create_signed_manifest(
            policy=default_policy(),
            signer_id="bad-private",
            private_key_b64=(base64.b64encode(b"x" * 31).decode("ascii")),
            issued_at=NOW,
        )


def test_fabricated_trust_is_not_authority():
    policy = default_policy().model_copy(deep=True)

    policy.fixed_versions["8.5"] = "8.5.13"

    fabricated = IntelligenceTrustDecision(
        state=(IntelligenceTrustState.TRUSTED),
        trusted=True,
        policy_id=policy.policy_id,
        policy_sha256=policy_sha256(policy),
        signer_id="fabricated",
        algorithm="ed25519",
    )

    resolved = resolve_policy_trust(
        policy,
        fabricated,
    )

    assert resolved.trusted is False

    assert resolved.state == IntelligenceTrustState.METADATA_MISMATCH


def test_custom_policy_without_activation_is_unsigned():
    policy = default_policy().model_copy(deep=True)

    policy.fixed_versions["8.5"] = "8.5.13"

    decision = resolve_policy_trust(policy)

    assert decision.trusted is False

    assert decision.state == IntelligenceTrustState.UNSIGNED


def test_verified_selection_constructor_is_sealed():
    policy = default_policy()

    trust = IntelligenceTrustDecision(
        state=(IntelligenceTrustState.BUNDLED_TRUSTED),
        trusted=True,
        policy_id=policy.policy_id,
        policy_sha256=policy_sha256(policy),
        signer_id="fabricated",
    )

    with pytest.raises(TypeError):
        VerifiedIntelligenceSelection(
            policy=policy,
            trust=trust,
            lifecycle=(bundled_lifecycle(policy)),
        )


def test_authorized_signer_rotation_is_accepted():
    old_private, old_public = key_pair()

    new_private, new_public = key_pair()

    policy = default_policy()

    old_manifest = create_signed_manifest(
        policy=policy,
        signer_id="old-signer",
        private_key_b64=old_private,
        issued_at=NOW,
        generation=5,
        expires_at=(NOW + timedelta(days=10)),
    )

    old_trust = verify_manifest(
        policy,
        old_manifest,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old-signer",
                    public_key_b64=(old_public),
                )
            ]
        ),
    )

    state = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=5,
                    policy_sha256=(old_trust.policy_sha256),
                    signer_id="old-signer",
                    accepted_at=NOW,
                )
            )
        }
    )

    new_manifest = create_signed_manifest(
        policy=policy,
        signer_id="new-signer",
        private_key_b64=new_private,
        issued_at=NOW,
        generation=6,
        expires_at=(NOW + timedelta(days=10)),
    )

    delegation = create_signed_signer_delegation(
        context="intelligence",
        predecessor_signer_id="old-signer",
        predecessor_private_key_b64=old_private,
        successor_signer_id="new-signer",
        successor_public_key_b64=new_public,
        sequence=1,
        minimum_successor_generation=6,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    new_trust = verify_manifest(
        policy,
        new_manifest,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="old-signer",
                    public_key_b64=(old_public),
                ),
                TrustedSigner(
                    signer_id="new-signer",
                    public_key_b64=(new_public),
                    # Compatibility metadata must no longer be authority.
                    authorized_predecessors=["old-signer"],
                ),
            ],
            delegations=[delegation],
        ),
        now=NOW,
    )

    decision = evaluate_lifecycle(
        policy=policy,
        manifest=new_manifest,
        trust=new_trust,
        state=state,
        now=NOW,
    )

    assert decision.activatable is True
    assert decision.state.value == "current"


def test_unapproved_signer_rotation_is_denied():
    new_private, new_public = key_pair()

    policy = default_policy()

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="new-signer",
        private_key_b64=new_private,
        issued_at=NOW,
        generation=6,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust = verify_manifest(
        policy,
        manifest,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="new-signer",
                    public_key_b64=(new_public),
                )
            ]
        ),
    )

    state = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=5,
                    policy_sha256=(trust.policy_sha256),
                    signer_id="old-signer",
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


def test_trust_store_read_rejects_symlink(
    tmp_path,
):
    outside = tmp_path / "outside-trust.json"
    outside.write_text(
        json.dumps(TrustStore().model_dump(mode="json")),
        encoding="utf-8",
    )

    trust_path = tmp_path / "trust.json"
    trust_path.symlink_to(outside)

    with pytest.raises(
        ValueError,
        match="symbolic link",
    ):
        load_trust_store(trust_path)


def test_trust_store_read_rejects_non_regular_file(
    tmp_path,
):
    trust_path = tmp_path / "trust.json"
    trust_path.mkdir()

    with pytest.raises(
        ValueError,
        match="not a regular file",
    ):
        load_trust_store(trust_path)


def test_oversized_trust_store_fails_closed(
    tmp_path,
):
    from php_sentinel.intelligence.trust import (
        TRUST_STORE_MAX_BYTES,
        load_trust_store,
    )

    path = tmp_path / "trust.json"
    path.write_bytes(b"{" + (b"x" * TRUST_STORE_MAX_BYTES))

    with pytest.raises(
        ValueError,
        match="maximum allowed size",
    ):
        load_trust_store(path)


def test_trust_store_rejects_excessive_signer_count():
    from pydantic import ValidationError

    from php_sentinel.models.intelligence_trust import (
        MAX_TRUST_STORE_SIGNERS,
        TrustedSigner,
        TrustStore,
    )

    signer = TrustedSigner(
        signer_id="base",
        public_key_b64=base64.b64encode(b"k" * 32).decode("ascii"),
    )

    with pytest.raises(ValidationError):
        TrustStore(
            signers=[
                signer.model_copy(update={"signer_id": f"signer-{index}"})
                for index in range(MAX_TRUST_STORE_SIGNERS + 1)
            ]
        )


def test_manifest_loader_rejects_oversized_file(
    tmp_path,
):
    from php_sentinel.intelligence.repository import (
        LOCAL_INTELLIGENCE_ARTIFACT_MAX_BYTES,
    )
    from php_sentinel.intelligence.trust import load_manifest

    path = tmp_path / "manifest.json"
    path.write_bytes(b"x" * (LOCAL_INTELLIGENCE_ARTIFACT_MAX_BYTES + 1))

    with pytest.raises(
        ValueError,
        match="maximum allowed size",
    ):
        load_manifest(path)
