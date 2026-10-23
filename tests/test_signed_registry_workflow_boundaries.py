import base64
import json
import socket
from datetime import UTC, datetime, timedelta

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.registry_trust import (
    create_signed_source_registry_manifest,
    stage_bundle_with_signed_registry,
    verify_signed_source_registry,
    verify_staged_bundle_with_signed_registry,
)
from php_sentinel.intelligence.repository import default_policy
from php_sentinel.intelligence.source_registry import (
    resolve_source_selection,
)
from php_sentinel.intelligence.trust import create_signed_manifest
from php_sentinel.models.intelligence_source import (
    IntelligenceSource,
    IntelligenceSourceChannel,
    IntelligenceSourceRegistry,
)
from php_sentinel.models.intelligence_trust import (
    TrustedSigner,
    TrustStore,
)

NOW = datetime(
    2026,
    10,
    23,
    19,
    0,
    tzinfo=UTC,
)


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


def registry_model(
    *,
    base_url: str = "https://updates.example.test/intel/",
    allowed_signer: str = "policy-signer",
) -> IntelligenceSourceRegistry:
    return IntelligenceSourceRegistry(
        sources=[
            IntelligenceSource(
                source_id="official",
                base_url=base_url,
                allowed_signer_ids=[allowed_signer],
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


def write_fixture(tmp_path):
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

    registry_path = tmp_path / "registry.json"
    registry_manifest_path = tmp_path / "registry-manifest.json"
    registry_trust_path = tmp_path / "registry-trust.json"
    registry_state_path = tmp_path / "registry-state.json"

    registry_path.write_text(
        json.dumps(registry.model_dump(mode="json")),
        encoding="utf-8",
    )

    registry_manifest_path.write_text(
        json.dumps(registry_manifest.model_dump(mode="json")),
        encoding="utf-8",
    )

    registry_trust_path.write_text(
        json.dumps(
            TrustStore(
                signers=[
                    TrustedSigner(
                        signer_id="registry-signer",
                        public_key_b64=registry_public,
                    )
                ]
            ).model_dump(mode="json")
        ),
        encoding="utf-8",
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

    intelligence_trust_path = tmp_path / "intelligence-trust.json"
    intelligence_state_path = tmp_path / "intelligence-state.json"

    intelligence_trust_path.write_text(
        json.dumps(
            TrustStore(
                signers=[
                    TrustedSigner(
                        signer_id="policy-signer",
                        public_key_b64=policy_public,
                    )
                ]
            ).model_dump(mode="json")
        ),
        encoding="utf-8",
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
        "registry_path": registry_path,
        "registry_manifest_path": registry_manifest_path,
        "registry_trust_path": registry_trust_path,
        "registry_state_path": registry_state_path,
        "intelligence_trust_path": intelligence_trust_path,
        "intelligence_state_path": intelligence_state_path,
        "policy_bytes": policy_bytes,
        "manifest_bytes": manifest_bytes,
    }


def client_for(
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


def tamper_registry_file(
    path,
):
    tampered = registry_model(
        base_url="https://evil.example.test/",
        allowed_signer="attacker",
    )

    path.write_text(
        json.dumps(tampered.model_dump(mode="json")),
        encoding="utf-8",
    )


def test_verified_registry_capability_keeps_authenticated_snapshot(
    tmp_path,
):
    fixture = write_fixture(tmp_path)

    verified = verify_signed_source_registry(
        registry_path=fixture["registry_path"],
        manifest_path=(fixture["registry_manifest_path"]),
        registry_trust_store_path=(fixture["registry_trust_path"]),
        registry_state_path=(fixture["registry_state_path"]),
        now=NOW,
    )

    tamper_registry_file(fixture["registry_path"])

    selection = resolve_source_selection(
        registry=verified.registry,
        source_id="official",
        channel="stable",
    )

    assert selection.policy_url == ("https://updates.example.test/intel/stable/policy.json")

    assert selection.allowed_signer_ids == ["policy-signer"]


def test_signed_staging_uses_authenticated_registry_snapshot(
    tmp_path,
):
    fixture = write_fixture(tmp_path)

    verified = verify_signed_source_registry(
        registry_path=fixture["registry_path"],
        manifest_path=(fixture["registry_manifest_path"]),
        registry_trust_store_path=(fixture["registry_trust_path"]),
        registry_state_path=(fixture["registry_state_path"]),
        now=NOW,
    )

    tamper_registry_file(fixture["registry_path"])

    # The lower-level authenticated primitive consumes the exact
    # verified model; the changed file is no longer consulted.
    from php_sentinel.intelligence.source_registry import (
        stage_registry_bundle_from_registry,
    )

    stage = tmp_path / "stage"

    with client_for(
        policy_bytes=fixture["policy_bytes"],
        manifest_bytes=fixture["manifest_bytes"],
    ) as client:
        metadata = stage_registry_bundle_from_registry(
            registry=verified.registry,
            source_id="official",
            channel="stable",
            staging_directory=stage,
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
            now=NOW,
        )

    assert metadata.policy_url.startswith("https://updates.example.test/intel/")

    assert metadata.source_id == "official"
    assert metadata.channel == "stable"


def test_signed_wrapper_rejects_tampered_registry_before_staging(
    tmp_path,
):
    fixture = write_fixture(tmp_path)

    tamper_registry_file(fixture["registry_path"])

    stage = tmp_path / "stage"

    with client_for(
        policy_bytes=fixture["policy_bytes"],
        manifest_bytes=fixture["manifest_bytes"],
    ) as client:
        try:
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
        except ValueError as exc:
            assert "trust verification failed" in str(exc)
        else:
            raise AssertionError("Tampered registry unexpectedly staged.")

    assert not stage.exists()


def test_signed_staging_is_read_only_for_registry_lifecycle(
    tmp_path,
):
    fixture = write_fixture(tmp_path)

    stage = tmp_path / "stage"

    with client_for(
        policy_bytes=fixture["policy_bytes"],
        manifest_bytes=fixture["manifest_bytes"],
    ) as client:
        verified_registry, metadata = stage_bundle_with_signed_registry(
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

    assert verified_registry.lifecycle.activatable
    assert metadata.source_id == "official"

    assert not fixture["registry_state_path"].exists()


def test_signed_verification_reauthenticates_registry_and_is_read_only(
    tmp_path,
):
    fixture = write_fixture(tmp_path)

    stage = tmp_path / "stage"

    with client_for(
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

    assert verified_registry.lifecycle.activatable
    assert candidate.trust.trusted
    assert candidate.lifecycle.activatable

    assert not fixture["registry_state_path"].exists()

    assert not fixture["intelligence_state_path"].exists()
