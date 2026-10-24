import base64
import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from php_sentinel.intelligence.registry_trust import (
    SourceRegistryVerificationError,
    activate_cached_intelligence_with_signed_registry,
    create_signed_source_registry_manifest,
    stage_bundle_with_signed_registry,
    verify_staged_bundle_with_signed_registry,
)
from php_sentinel.intelligence.repository import default_policy
from php_sentinel.intelligence.source_registry import (
    IntelligenceSourceRegistryError,
    promote_registry_candidate,
)
from php_sentinel.intelligence.trust import create_signed_manifest
from php_sentinel.models.intelligence_source import (
    IntelligenceSource,
    IntelligenceSourceChannel,
    IntelligenceSourceRegistry,
)
from php_sentinel.models.intelligence_trust import TrustedSigner, TrustStore

NOW = datetime(
    2026,
    10,
    23,
    19,
    0,
    tzinfo=UTC,
)


def key_pair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()

    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


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


def public_test_peer_address(
    response,
):
    return "8.8.8.8"


def registry_model(
    *,
    base_url: str = "https://updates.example.test/intel/",
    allowed_signer_ids: list[str] | None = None,
) -> IntelligenceSourceRegistry:
    return IntelligenceSourceRegistry(
        sources=[
            IntelligenceSource(
                source_id="official",
                base_url=base_url,
                allowed_signer_ids=(
                    ["policy-signer"] if allowed_signer_ids is None else allowed_signer_ids
                ),
                channels=[
                    IntelligenceSourceChannel(
                        channel="stable",
                        policy_path="stable/policy.json",
                        manifest_path="stable/manifest.json",
                        minimum_generation=5,
                    )
                ],
            )
        ]
    )


def write_json(
    path: Path,
    value,
) -> None:
    path.write_text(
        json.dumps(
            value,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def build_fixture(
    tmp_path,
):
    registry_private, registry_public = key_pair()
    policy_private, policy_public = key_pair()

    registry = registry_model()

    registry_manifest = create_signed_source_registry_manifest(
        registry=registry,
        signer_id="registry-signer",
        private_key_b64=registry_private,
        generation=5,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    policy = default_policy()

    policy_manifest = create_signed_manifest(
        policy=policy,
        signer_id="policy-signer",
        private_key_b64=policy_private,
        generation=5,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    registry_path = tmp_path / "registry.json"
    registry_manifest_path = tmp_path / "registry-manifest.json"
    registry_trust_path = tmp_path / "registry-trust.json"
    registry_state_path = tmp_path / "registry-state.json"

    intelligence_trust_path = tmp_path / "intelligence-trust.json"
    intelligence_state_path = tmp_path / "intelligence-state.json"

    write_json(
        registry_path,
        registry.model_dump(mode="json"),
    )

    write_json(
        registry_manifest_path,
        registry_manifest.model_dump(mode="json"),
    )

    write_json(
        registry_trust_path,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="registry-signer",
                    public_key_b64=registry_public,
                )
            ]
        ).model_dump(mode="json"),
    )

    write_json(
        intelligence_trust_path,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="policy-signer",
                    public_key_b64=policy_public,
                )
            ]
        ).model_dump(mode="json"),
    )

    policy_bytes = json.dumps(
        policy.model_dump(mode="json"),
        sort_keys=True,
    ).encode("utf-8")

    manifest_bytes = json.dumps(
        policy_manifest.model_dump(mode="json"),
        sort_keys=True,
    ).encode("utf-8")

    return {
        "registry": registry,
        "registry_private": registry_private,
        "registry_path": registry_path,
        "registry_manifest_path": registry_manifest_path,
        "registry_trust_path": registry_trust_path,
        "registry_state_path": registry_state_path,
        "intelligence_trust_path": intelligence_trust_path,
        "intelligence_state_path": intelligence_state_path,
        "policy": policy,
        "policy_bytes": policy_bytes,
        "manifest_bytes": manifest_bytes,
    }


def update_client(
    *,
    policy_bytes: bytes,
    manifest_bytes: bytes,
):
    expected_policy = "https://updates.example.test/intel/stable/policy.json"
    expected_manifest = "https://updates.example.test/intel/stable/manifest.json"

    def handler(request):
        url = str(request.url)

        if url == expected_policy:
            return httpx.Response(
                200,
                content=policy_bytes,
                request=request,
            )

        if url == expected_manifest:
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


def stage_verify_promote(
    *,
    tmp_path,
    fixture,
):
    stage = tmp_path / "stage"

    with update_client(
        policy_bytes=fixture["policy_bytes"],
        manifest_bytes=fixture["manifest_bytes"],
    ) as client:
        stage_bundle_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            staging_directory=stage,
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
            now=NOW,
        )

    verified_registry, candidate = verify_staged_bundle_with_signed_registry(
        registry_path=fixture["registry_path"],
        registry_manifest_path=(fixture["registry_manifest_path"]),
        registry_trust_store_path=(fixture["registry_trust_path"]),
        registry_state_path=(fixture["registry_state_path"]),
        source_id="official",
        channel="stable",
        staging_directory=stage,
        intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
        intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
        now=NOW,
    )

    destination = promote_registry_candidate(
        candidate=candidate,
        verified_root=(tmp_path / "verified"),
        expected_source_id="official",
        expected_channel="stable",
    )

    return (
        verified_registry,
        candidate,
        destination,
    )


def resign_registry(
    *,
    fixture,
    registry,
    generation: int = 6,
):
    manifest = create_signed_source_registry_manifest(
        registry=registry,
        signer_id="registry-signer",
        private_key_b64=fixture["registry_private"],
        generation=generation,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    write_json(
        fixture["registry_path"],
        registry.model_dump(mode="json"),
    )

    write_json(
        fixture["registry_manifest_path"],
        manifest.model_dump(mode="json"),
    )


def test_complete_signed_supply_chain_reaches_authoritative_activation(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    (
        verified_registry,
        candidate,
        destination,
    ) = stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    assert verified_registry.lifecycle.activatable
    assert candidate.trust.trusted
    assert candidate.lifecycle.activatable
    assert destination.is_dir()

    (
        activated_registry,
        entry,
        activated,
    ) = activate_cached_intelligence_with_signed_registry(
        registry_path=fixture["registry_path"],
        registry_manifest_path=(fixture["registry_manifest_path"]),
        registry_trust_store_path=(fixture["registry_trust_path"]),
        registry_state_path=(fixture["registry_state_path"]),
        source_id="official",
        channel="stable",
        verified_root=(tmp_path / "verified"),
        intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
        intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
        now=NOW,
    )

    assert activated_registry.lifecycle.activatable
    assert entry.source_id == "official"
    assert entry.channel == "stable"
    assert activated.policy.policy_id == fixture["policy"].policy_id
    assert activated.trust.trusted
    assert activated.trust.signer_id == "policy-signer"
    assert activated.lifecycle.activatable

    assert fixture["registry_state_path"].exists()
    assert fixture["intelligence_state_path"].exists()


def test_registry_tampering_after_cache_promotion_blocks_activation(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    tampered_registry = registry_model(
        base_url="https://evil.example.test/",
        allowed_signer_ids=["attacker"],
    )

    write_json(
        fixture["registry_path"],
        tampered_registry.model_dump(mode="json"),
    )

    with pytest.raises(
        SourceRegistryVerificationError,
        match="trust verification failed",
    ):
        activate_cached_intelligence_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
            intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
            now=NOW,
        )

    assert not fixture["registry_state_path"].exists()
    assert not fixture["intelligence_state_path"].exists()


def test_resigned_registry_url_change_invalidates_cached_provenance(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    changed_registry = registry_model(
        base_url="https://updates.example.test/new-intel/",
    )

    resign_registry(
        fixture=fixture,
        registry=changed_registry,
    )

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="current source/channel URL policy",
    ):
        activate_cached_intelligence_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
            intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
            now=NOW,
        )

    assert fixture["registry_state_path"].exists()
    assert not fixture["intelligence_state_path"].exists()


def test_resigned_registry_signer_restriction_invalidates_cached_bundle(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    restricted_registry = registry_model(
        allowed_signer_ids=["other-policy-signer"],
    )

    resign_registry(
        fixture=fixture,
        registry=restricted_registry,
    )

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="Cached signer is not authorized",
    ):
        activate_cached_intelligence_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
            intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
            now=NOW,
        )

    assert fixture["registry_state_path"].exists()
    assert not fixture["intelligence_state_path"].exists()


def test_current_intelligence_trust_revocation_blocks_previously_cached_bundle(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    write_json(
        fixture["intelligence_trust_path"],
        TrustStore(signers=[]).model_dump(mode="json"),
    )

    with pytest.raises(
        ValueError,
        match="unknown_signer",
    ):
        activate_cached_intelligence_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
            intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
            now=NOW,
        )

    assert fixture["registry_state_path"].exists()
    assert not fixture["intelligence_state_path"].exists()


def test_cache_artifact_tampering_after_promotion_blocks_activation(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    (
        _,
        _,
        destination,
    ) = stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    policy_path = destination / "policy.json"

    policy_path.write_bytes(policy_path.read_bytes() + b"\n")

    with pytest.raises(
        ValueError,
    ):
        activate_cached_intelligence_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
            intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
            now=NOW,
        )

    assert fixture["registry_state_path"].exists()
    assert not fixture["intelligence_state_path"].exists()


def test_registry_lifecycle_rollback_blocks_cached_activation(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    (
        _,
        _,
        _,
    ) = activate_cached_intelligence_with_signed_registry(
        registry_path=fixture["registry_path"],
        registry_manifest_path=(fixture["registry_manifest_path"]),
        registry_trust_store_path=(fixture["registry_trust_path"]),
        registry_state_path=(fixture["registry_state_path"]),
        source_id="official",
        channel="stable",
        verified_root=(tmp_path / "verified"),
        intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
        intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
        now=NOW,
    )

    older_registry = registry_model()

    older_manifest = create_signed_source_registry_manifest(
        registry=older_registry,
        signer_id="registry-signer",
        private_key_b64=fixture["registry_private"],
        generation=4,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    write_json(
        fixture["registry_path"],
        older_registry.model_dump(mode="json"),
    )

    write_json(
        fixture["registry_manifest_path"],
        older_manifest.model_dump(mode="json"),
    )

    with pytest.raises(
        SourceRegistryVerificationError,
        match="rollback_detected",
    ):
        activate_cached_intelligence_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
            intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
            now=NOW,
        )


def test_intelligence_lifecycle_rollback_blocks_cached_activation(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    (
        _,
        _,
        destination,
    ) = stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    (
        _,
        _,
        activated,
    ) = activate_cached_intelligence_with_signed_registry(
        registry_path=fixture["registry_path"],
        registry_manifest_path=(fixture["registry_manifest_path"]),
        registry_trust_store_path=(fixture["registry_trust_path"]),
        registry_state_path=(fixture["registry_state_path"]),
        source_id="official",
        channel="stable",
        verified_root=(tmp_path / "verified"),
        intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
        intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
        now=NOW,
    )

    assert activated.lifecycle.generation == 5

    manifest = json.loads(
        (destination / "manifest.json").read_text(
            encoding="utf-8",
        )
    )

    manifest["generation"] = 4

    write_json(
        destination / "manifest.json",
        manifest,
    )

    with pytest.raises(
        ValueError,
    ):
        activate_cached_intelligence_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
            intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
            now=NOW,
        )


def test_cached_provenance_metadata_tampering_blocks_signed_activation(
    tmp_path,
):
    fixture = build_fixture(tmp_path)

    (
        _,
        _,
        destination,
    ) = stage_verify_promote(
        tmp_path=tmp_path,
        fixture=fixture,
    )

    verification_path = destination / "verification.json"

    metadata = json.loads(
        verification_path.read_text(
            encoding="utf-8",
        )
    )

    metadata["source_policy_url"] = "https://evil.example.test/policy.json"

    write_json(
        verification_path,
        metadata,
    )

    with pytest.raises(
        ValueError,
    ):
        activate_cached_intelligence_with_signed_registry(
            registry_path=fixture["registry_path"],
            registry_manifest_path=(fixture["registry_manifest_path"]),
            registry_trust_store_path=(fixture["registry_trust_path"]),
            registry_state_path=(fixture["registry_state_path"]),
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            intelligence_trust_store_path=(fixture["intelligence_trust_path"]),
            intelligence_lifecycle_state_path=(fixture["intelligence_state_path"]),
            now=NOW,
        )
