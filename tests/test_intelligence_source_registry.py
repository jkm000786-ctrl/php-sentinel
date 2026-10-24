import base64
import json
import socket
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.repository import (
    default_policy,
)
from php_sentinel.intelligence.source_registry import (
    IntelligenceSourceRegistryError,
    _url_is_within_source_base,
    activate_registry_cached_intelligence,
    load_source_registry,
    promote_registry_candidate,
    resolve_source_selection,
    stage_registry_bundle,
    verify_registry_staged_bundle,
)
from php_sentinel.intelligence.trust import (
    create_signed_manifest,
)
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
    18,
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


def key_material():
    key = Ed25519PrivateKey.generate()

    private_raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=(serialization.NoEncryption()),
    )

    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def registry_model(
    *,
    enabled=True,
    channel_enabled=True,
    minimum_generation=5,
    signer_id="source-signer",
):
    return IntelligenceSourceRegistry(
        sources=[
            IntelligenceSource(
                source_id="official",
                enabled=enabled,
                base_url=("https://updates.example.test/intel/"),
                allowed_signer_ids=[signer_id],
                channels=[
                    IntelligenceSourceChannel(
                        channel="stable",
                        enabled=(channel_enabled),
                        policy_path=("stable/policy.json"),
                        manifest_path=("stable/manifest.json"),
                        minimum_generation=(minimum_generation),
                    )
                ],
            )
        ]
    )


def write_registry(
    tmp_path,
    registry,
):
    path = tmp_path / "registry.json"

    path.write_text(
        json.dumps(registry.model_dump(mode="json")),
        encoding="utf-8",
    )

    return path


def bundle(
    *,
    generation=5,
    signer_id="source-signer",
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

    policy_bytes = json.dumps(
        policy.model_dump(mode="json"),
        sort_keys=True,
    ).encode("utf-8")

    manifest_bytes = json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
    ).encode("utf-8")

    trust = TrustStore(
        signers=[
            TrustedSigner(
                signer_id=signer_id,
                public_key_b64=(public_b64),
            )
        ]
    )

    return (
        policy_bytes,
        manifest_bytes,
        trust,
    )


def mock_client(
    policy_bytes,
    manifest_bytes,
):
    policy_url = "https://updates.example.test/intel/stable/policy.json"

    manifest_url = "https://updates.example.test/intel/stable/manifest.json"

    def handler(request):
        if str(request.url) == policy_url:
            return httpx.Response(
                200,
                content=policy_bytes,
                request=request,
            )

        if str(request.url) == manifest_url:
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


def setup_source_bundle(
    tmp_path,
    *,
    generation=5,
    signer_id="source-signer",
    registry_signer_id=None,
    minimum_generation=5,
):
    if registry_signer_id is None:
        registry_signer_id = signer_id

    registry = registry_model(
        signer_id=registry_signer_id,
        minimum_generation=(minimum_generation),
    )

    registry_path = write_registry(
        tmp_path,
        registry,
    )

    (
        policy_bytes,
        manifest_bytes,
        trust,
    ) = bundle(
        generation=generation,
        signer_id=signer_id,
    )

    trust_path = tmp_path / "trust.json"

    trust_path.write_text(
        json.dumps(trust.model_dump(mode="json")),
        encoding="utf-8",
    )

    stage = tmp_path / "stage"

    with mock_client(
        policy_bytes,
        manifest_bytes,
    ) as client:
        metadata = stage_registry_bundle(
            registry_path=registry_path,
            source_id="official",
            channel="stable",
            staging_directory=stage,
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
            now=NOW,
        )

    return (
        registry_path,
        trust_path,
        stage,
        metadata,
    )


def test_registry_requires_https():
    with pytest.raises(
        ValueError,
        match="HTTPS",
    ):
        IntelligenceSource(
            source_id="bad",
            base_url=("http://updates.example.test/"),
            allowed_signer_ids=["signer"],
            channels=[
                IntelligenceSourceChannel(
                    channel="stable",
                    policy_path="policy.json",
                    manifest_path="manifest.json",
                )
            ],
        )


def test_registry_rejects_duplicate_source_ids():
    source = IntelligenceSource(
        source_id="official",
        base_url=("https://updates.example.test/"),
        allowed_signer_ids=["signer"],
        channels=[
            IntelligenceSourceChannel(
                channel="stable",
                policy_path="policy.json",
                manifest_path="manifest.json",
            )
        ],
    )

    with pytest.raises(
        ValueError,
        match="source IDs",
    ):
        IntelligenceSourceRegistry(
            sources=[
                source,
                source,
            ]
        )


def test_disabled_source_fails_closed(
    tmp_path,
):
    registry_path = write_registry(
        tmp_path,
        registry_model(enabled=False),
    )

    loaded = load_source_registry(registry_path)

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="disabled",
    ):
        resolve_source_selection(
            registry=loaded,
            source_id="official",
            channel="stable",
        )


def test_disabled_channel_fails_closed(
    tmp_path,
):
    registry_path = write_registry(
        tmp_path,
        registry_model(channel_enabled=False),
    )

    loaded = load_source_registry(registry_path)

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="disabled",
    ):
        resolve_source_selection(
            registry=loaded,
            source_id="official",
            channel="stable",
        )


def test_source_resolution_is_deterministic(
    tmp_path,
):
    registry_path = write_registry(tmp_path, registry_model())

    loaded = load_source_registry(registry_path)

    selection = resolve_source_selection(
        registry=loaded,
        source_id="official",
        channel="stable",
    )

    assert selection.policy_url == ("https://updates.example.test/intel/stable/policy.json")

    assert selection.manifest_url == ("https://updates.example.test/intel/stable/manifest.json")

    assert selection.minimum_generation == 5


def test_stage_records_source_channel_provenance(
    tmp_path,
):
    (
        _,
        _,
        _,
        metadata,
    ) = setup_source_bundle(tmp_path)

    assert metadata.source_id == "official"
    assert metadata.channel == "stable"


def test_source_signer_policy_only_narrows_trust(
    tmp_path,
):
    (
        registry_path,
        trust_path,
        stage,
        _,
    ) = setup_source_bundle(
        tmp_path,
        signer_id="globally-trusted",
        registry_signer_id=("different-source-signer"),
    )

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="not authorized",
    ):
        verify_registry_staged_bundle(
            registry_path=registry_path,
            source_id="official",
            channel="stable",
            staging_directory=stage,
            trust_store_path=trust_path,
            lifecycle_state_path=(tmp_path / "lifecycle.json"),
            now=NOW,
        )


def test_source_minimum_generation_strengthens_operator_minimum(
    tmp_path,
):
    (
        registry_path,
        trust_path,
        stage,
        _,
    ) = setup_source_bundle(
        tmp_path,
        generation=4,
        minimum_generation=5,
    )

    with pytest.raises(
        ValueError,
        match="below_minimum_generation",
    ):
        verify_registry_staged_bundle(
            registry_path=registry_path,
            source_id="official",
            channel="stable",
            staging_directory=stage,
            trust_store_path=trust_path,
            lifecycle_state_path=(tmp_path / "lifecycle.json"),
            minimum_generation=1,
            now=NOW,
        )


def test_source_channel_mismatch_is_rejected(
    tmp_path,
):
    (
        registry_path,
        trust_path,
        stage,
        metadata,
    ) = setup_source_bundle(tmp_path)

    metadata = metadata.model_copy(update={"channel": "testing"})

    (stage / "stage-metadata.json").write_text(
        json.dumps(metadata.model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="provenance",
    ):
        verify_registry_staged_bundle(
            registry_path=registry_path,
            source_id="official",
            channel="stable",
            staging_directory=stage,
            trust_store_path=trust_path,
            lifecycle_state_path=(tmp_path / "lifecycle.json"),
            now=NOW,
        )


def test_registry_cache_activation_reverifies_current_authority(
    tmp_path,
):
    (
        registry_path,
        trust_path,
        stage,
        _,
    ) = setup_source_bundle(
        tmp_path,
        generation=5,
    )

    state_path = tmp_path / "lifecycle.json"

    candidate = verify_registry_staged_bundle(
        registry_path=registry_path,
        source_id="official",
        channel="stable",
        staging_directory=stage,
        trust_store_path=trust_path,
        lifecycle_state_path=(state_path),
        now=NOW,
    )

    destination = promote_registry_candidate(
        candidate=candidate,
        verified_root=(tmp_path / "verified"),
        expected_source_id="official",
        expected_channel="stable",
    )

    assert destination.exists()

    entry, selection = activate_registry_cached_intelligence(
        registry_path=registry_path,
        source_id="official",
        channel="stable",
        verified_root=(tmp_path / "verified"),
        trust_store_path=(trust_path),
        lifecycle_state_path=(state_path),
        now=NOW,
    )

    assert entry.source_id == "official"
    assert entry.channel == "stable"
    assert selection.trust.trusted is True
    assert selection.lifecycle.activatable is True


def test_url_containment_accepts_same_https_origin_and_subpath():
    assert _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test/intel/stable/policy.json"),
    )


def test_url_containment_rejects_prefix_confusion_host():
    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test.evil/intel/stable/policy.json"),
    )


def test_url_containment_rejects_different_port():
    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test:8443/intel/stable/policy.json"),
    )


def test_url_containment_treats_explicit_443_as_https_default():
    assert _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test:443/intel/stable/policy.json"),
    )


def test_url_containment_rejects_sibling_path_prefix():
    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test/intelligence/stable/policy.json"),
    )


def test_url_containment_rejects_parent_path():
    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test/stable/policy.json"),
    )


def test_url_containment_rejects_query_and_fragment():
    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test/intel/stable/policy.json?mirror=evil"),
    )

    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test/intel/stable/policy.json#fragment"),
    )


def test_url_containment_rejects_embedded_credentials():
    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://user:pass@updates.example.test/intel/stable/policy.json"),
    )


@pytest.mark.parametrize(
    "candidate_url",
    [
        "https://updates.example.test/intel/../admin/policy.json",
        "https://updates.example.test/intel/%2e%2e/admin/policy.json",
        "https://updates.example.test/intel/%2E%2E/admin/policy.json",
        "https://updates.example.test/intel/%252e%252e/admin/policy.json",
        "https://updates.example.test/intel/%2f..%2fadmin/policy.json",
        "https://updates.example.test/intel/%5c..%5cadmin/policy.json",
    ],
)
def test_url_containment_rejects_structural_path_ambiguity(
    candidate_url,
):
    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=candidate_url,
    )


def test_url_containment_rejects_malformed_port():
    assert not _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test:99999/intel/stable/policy.json"),
    )


@pytest.mark.parametrize(
    "candidate_url",
    [
        "https://[fe80::1%25eth0]/intel/policy.json",
        "https://[fe80::1%eth0]/intel/policy.json",
    ],
)
def test_url_containment_rejects_scoped_host_identity(
    candidate_url,
):
    assert not _url_is_within_source_base(
        base_url="https://[fe80::1]/intel/",
        candidate_url=candidate_url,
    )


def test_url_containment_allows_nonstructural_percent_encoding():
    assert _url_is_within_source_base(
        base_url="https://updates.example.test/intel/",
        candidate_url=("https://updates.example.test/intel/release%20notes/policy.json"),
    )


def test_registry_cache_activation_rejects_stale_source_urls(
    tmp_path,
):
    (
        registry_path,
        trust_path,
        stage,
        _,
    ) = setup_source_bundle(
        tmp_path,
        generation=5,
    )

    state_path = tmp_path / "lifecycle.json"

    candidate = verify_registry_staged_bundle(
        registry_path=registry_path,
        source_id="official",
        channel="stable",
        staging_directory=stage,
        trust_store_path=trust_path,
        lifecycle_state_path=state_path,
        now=NOW,
    )

    destination = promote_registry_candidate(
        candidate=candidate,
        verified_root=(tmp_path / "verified"),
        expected_source_id="official",
        expected_channel="stable",
    )

    assert destination.exists()

    changed_registry = registry_model()
    changed_registry.sources[0].base_url = "https://updates.example.test/new-intel/"

    registry_path.write_text(
        json.dumps(changed_registry.model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="current source/channel URL policy",
    ):
        activate_registry_cached_intelligence(
            registry_path=registry_path,
            source_id="official",
            channel="stable",
            verified_root=(tmp_path / "verified"),
            trust_store_path=trust_path,
            lifecycle_state_path=state_path,
            now=NOW,
        )


def test_source_registry_rejects_excessive_source_count():
    from pydantic import ValidationError

    from php_sentinel.models.intelligence_source import (
        MAX_SOURCE_REGISTRY_SOURCES,
        IntelligenceSourceRegistry,
    )

    source = registry_model().sources[0]

    with pytest.raises(ValidationError):
        IntelligenceSourceRegistry(
            sources=[
                source.model_copy(update={"source_id": f"source-{index}"})
                for index in range(MAX_SOURCE_REGISTRY_SOURCES + 1)
            ]
        )


def test_source_rejects_excessive_channels_and_signers():
    from pydantic import ValidationError

    from php_sentinel.models.intelligence_source import (
        MAX_SOURCE_ALLOWED_SIGNERS,
        MAX_SOURCE_CHANNELS_PER_SOURCE,
        IntelligenceSource,
        IntelligenceSourceChannel,
    )

    channel = IntelligenceSourceChannel(
        channel="stable",
        policy_path="policy.json",
        manifest_path="manifest.json",
    )

    with pytest.raises(ValidationError):
        IntelligenceSource(
            source_id="bounded",
            base_url="https://example.com/",
            allowed_signer_ids=["signer"],
            channels=[
                channel.model_copy(update={"channel": f"channel-{index}"})
                for index in range(MAX_SOURCE_CHANNELS_PER_SOURCE + 1)
            ],
        )

    with pytest.raises(ValidationError):
        IntelligenceSource(
            source_id="bounded",
            base_url="https://example.com/",
            allowed_signer_ids=[
                f"signer-{index}" for index in range(MAX_SOURCE_ALLOWED_SIGNERS + 1)
            ],
            channels=[channel],
        )


def test_source_registry_loader_rejects_oversized_file(
    tmp_path,
):
    from php_sentinel.intelligence.repository import (
        LOCAL_INTELLIGENCE_ARTIFACT_MAX_BYTES,
    )

    path = tmp_path / "registry.json"
    path.write_bytes(b"x" * (LOCAL_INTELLIGENCE_ARTIFACT_MAX_BYTES + 1))

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="unreadable or invalid",
    ):
        load_source_registry(path)
