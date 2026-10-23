import base64
import hashlib
import json
import socket
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.lifecycle import (
    load_lifecycle_state,
    save_lifecycle_state,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_sha256,
)
from php_sentinel.intelligence.trust import (
    create_signed_manifest,
)
from php_sentinel.intelligence.update import (
    IntelligenceUpdatePromotionError,
    IntelligenceUpdateTransportError,
    IntelligenceUpdateVerificationError,
    promote_verified_candidate,
    stage_remote_bundle,
    verify_staged_bundle,
)
from php_sentinel.models.intelligence_lifecycle import (
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

POLICY_URL = "https://updates.example.test/policy.json"

MANIFEST_URL = "https://updates.example.test/manifest.json"


def public_test_peer_address(
    response,
):
    return "8.8.8.8"


def public_test_resolver(
    host,
    port,
    *,
    type,
):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (
                "8.8.8.8",
                port,
            ),
        )
    ]


def key_material():
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


def bundle(
    *,
    generation=5,
    signer_id="update-signer",
):
    private_b64, public_b64 = key_material()

    policy = default_policy().model_copy(deep=True)

    manifest = create_signed_manifest(
        policy=policy,
        signer_id=signer_id,
        private_key_b64=private_b64,
        issued_at=NOW,
        generation=generation,
        expires_at=(NOW + timedelta(days=10)),
    )

    trust_store = TrustStore(
        signers=[
            TrustedSigner(
                signer_id=signer_id,
                public_key_b64=(public_b64),
            )
        ]
    )

    policy_bytes = json.dumps(
        policy.model_dump(mode="json"),
        sort_keys=True,
    ).encode("utf-8")

    manifest_bytes = json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
    ).encode("utf-8")

    return (
        policy,
        manifest,
        trust_store,
        policy_bytes,
        manifest_bytes,
    )


def client_for(
    policy_bytes,
    manifest_bytes,
):
    def handler(
        request,
    ):
        if str(request.url) == POLICY_URL:
            return httpx.Response(
                200,
                content=policy_bytes,
                request=request,
            )

        if str(request.url) == MANIFEST_URL:
            return httpx.Response(
                200,
                content=manifest_bytes,
                request=request,
            )

        return httpx.Response(
            404,
            request=request,
        )

    return httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )


def write_trust_store(
    tmp_path,
    trust_store,
):
    path = tmp_path / "trust.json"

    path.write_text(
        json.dumps(trust_store.model_dump(mode="json")),
        encoding="utf-8",
    )

    return path


def stage_valid_bundle(
    tmp_path,
    *,
    generation=5,
):
    (
        policy,
        manifest,
        trust_store,
        policy_bytes,
        manifest_bytes,
    ) = bundle(generation=generation)

    stage = tmp_path / "stage"

    with client_for(
        policy_bytes,
        manifest_bytes,
    ) as client:
        metadata = stage_remote_bundle(
            policy_url=POLICY_URL,
            manifest_url=MANIFEST_URL,
            staging_directory=stage,
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
            now=NOW,
        )

    trust_path = write_trust_store(
        tmp_path,
        trust_store,
    )

    state_path = tmp_path / "lifecycle.json"

    return (
        policy,
        manifest,
        metadata,
        stage,
        trust_path,
        state_path,
    )


def test_non_https_update_url_is_rejected(
    tmp_path,
):
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="HTTPS",
    ):
        stage_remote_bundle(
            policy_url=("http://updates.example.test/policy.json"),
            manifest_url=(MANIFEST_URL),
            staging_directory=(tmp_path / "stage"),
        )


def test_stage_records_transport_digests(
    tmp_path,
):
    (
        _,
        _,
        metadata,
        stage,
        _,
        _,
    ) = stage_valid_bundle(tmp_path)

    policy_bytes = stage.joinpath("policy.json").read_bytes()

    assert metadata.policy_transport_sha256 == hashlib.sha256(policy_bytes).hexdigest()

    assert metadata.policy_url == POLICY_URL
    assert metadata.manifest_url == MANIFEST_URL


def test_transport_success_does_not_create_trust(
    tmp_path,
):
    (
        _,
        _,
        _,
        stage,
        _,
        state_path,
    ) = stage_valid_bundle(tmp_path)

    empty_trust = tmp_path / "empty-trust.json"

    empty_trust.write_text(
        json.dumps(TrustStore().model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceUpdateVerificationError,
        match="unknown_signer",
    ):
        verify_staged_bundle(
            staging_directory=stage,
            trust_store_path=(empty_trust),
            lifecycle_state_path=(state_path),
            now=NOW,
        )


def test_verification_does_not_mutate_lifecycle_state(
    tmp_path,
):
    (
        _,
        _,
        _,
        stage,
        trust_path,
        state_path,
    ) = stage_valid_bundle(tmp_path)

    candidate = verify_staged_bundle(
        staging_directory=stage,
        trust_store_path=trust_path,
        lifecycle_state_path=(state_path),
        now=NOW,
    )

    assert candidate.trust.trusted is True

    assert candidate.lifecycle.activatable is True

    assert not state_path.exists()


def test_rollback_candidate_is_not_verified(
    tmp_path,
):
    (
        policy,
        _,
        _,
        stage,
        trust_path,
        state_path,
    ) = stage_valid_bundle(
        tmp_path,
        generation=4,
    )

    save_lifecycle_state(
        state_path,
        LifecycleStateStore(
            records={
                policy.policy_id: (
                    LifecycleStateRecord(
                        generation=5,
                        policy_sha256=(policy_sha256(policy)),
                        signer_id=("update-signer"),
                        accepted_at=NOW,
                    )
                )
            }
        ),
    )

    with pytest.raises(
        IntelligenceUpdateVerificationError,
        match="rollback_detected",
    ):
        verify_staged_bundle(
            staging_directory=stage,
            trust_store_path=(trust_path),
            lifecycle_state_path=(state_path),
            now=NOW,
        )


def test_staged_transport_tampering_is_detected(
    tmp_path,
):
    (
        _,
        _,
        _,
        stage,
        trust_path,
        state_path,
    ) = stage_valid_bundle(tmp_path)

    with (stage / "policy.json").open("ab") as handle:
        handle.write(b" ")

    with pytest.raises(
        IntelligenceUpdateVerificationError,
        match=r"transport (?:byte count|digest) changed",
    ):
        verify_staged_bundle(
            staging_directory=stage,
            trust_store_path=(trust_path),
            lifecycle_state_path=(state_path),
            now=NOW,
        )


def test_verified_candidate_promotes_to_immutable_cache(
    tmp_path,
):
    (
        _,
        _,
        _,
        stage,
        trust_path,
        state_path,
    ) = stage_valid_bundle(tmp_path)

    candidate = verify_staged_bundle(
        staging_directory=stage,
        trust_store_path=trust_path,
        lifecycle_state_path=(state_path),
        now=NOW,
    )

    destination = promote_verified_candidate(
        candidate=candidate,
        verified_root=(tmp_path / "verified"),
    )

    assert (destination / "policy.json").exists()

    assert (destination / "manifest.json").exists()

    assert (destination / "verification.json").exists()

    assert not state_path.exists()


def test_promotion_rejects_post_verification_tampering(
    tmp_path,
):
    (
        _,
        _,
        _,
        stage,
        trust_path,
        state_path,
    ) = stage_valid_bundle(tmp_path)

    candidate = verify_staged_bundle(
        staging_directory=stage,
        trust_store_path=trust_path,
        lifecycle_state_path=(state_path),
        now=NOW,
    )

    manifest_path = stage / "manifest.json"

    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")

    with pytest.raises(
        (
            IntelligenceUpdatePromotionError,
            IntelligenceUpdateVerificationError,
        )
    ):
        promote_verified_candidate(
            candidate=candidate,
            verified_root=(tmp_path / "verified"),
        )


def test_verification_reads_state_without_advancing_it(
    tmp_path,
):
    (
        policy,
        _,
        _,
        stage,
        trust_path,
        state_path,
    ) = stage_valid_bundle(
        tmp_path,
        generation=6,
    )

    initial = LifecycleStateStore(
        records={
            policy.policy_id: (
                LifecycleStateRecord(
                    generation=5,
                    policy_sha256=(policy_sha256(policy)),
                    signer_id=("update-signer"),
                    accepted_at=NOW,
                )
            )
        }
    )

    save_lifecycle_state(
        state_path,
        initial,
    )

    candidate = verify_staged_bundle(
        staging_directory=stage,
        trust_store_path=trust_path,
        lifecycle_state_path=(state_path),
        now=NOW,
    )

    persisted = load_lifecycle_state(state_path)

    assert candidate.lifecycle.generation == 6

    assert persisted.records[policy.policy_id].generation == 5


def test_staged_policy_byte_count_metadata_tampering_is_detected(
    tmp_path,
):
    (
        _,
        _,
        metadata,
        stage,
        trust_path,
        state_path,
    ) = stage_valid_bundle(tmp_path)

    tampered = metadata.model_copy(
        update={
            "policy_bytes": metadata.policy_bytes + 1,
        }
    )

    (stage / "stage-metadata.json").write_text(
        json.dumps(tampered.model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceUpdateVerificationError,
        match="policy transport byte count changed",
    ):
        verify_staged_bundle(
            staging_directory=stage,
            trust_store_path=trust_path,
            lifecycle_state_path=state_path,
            now=NOW,
        )


def test_staged_manifest_byte_count_metadata_tampering_is_detected(
    tmp_path,
):
    (
        _,
        _,
        metadata,
        stage,
        trust_path,
        state_path,
    ) = stage_valid_bundle(tmp_path)

    tampered = metadata.model_copy(
        update={
            "manifest_bytes": metadata.manifest_bytes + 1,
        }
    )

    (stage / "stage-metadata.json").write_text(
        json.dumps(tampered.model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceUpdateVerificationError,
        match="manifest transport byte count changed",
    ):
        verify_staged_bundle(
            staging_directory=stage,
            trust_store_path=trust_path,
            lifecycle_state_path=state_path,
            now=NOW,
        )
