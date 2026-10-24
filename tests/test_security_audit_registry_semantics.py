from __future__ import annotations

import base64
import json
import socket
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from php_sentinel.intelligence.repository import default_policy
from php_sentinel.intelligence.security_audit import read_security_audit_events
from php_sentinel.intelligence.source_registry import (
    IntelligenceSourceRegistryError,
    stage_registry_bundle_from_registry,
    verify_registry_staged_bundle_from_registry,
)
from php_sentinel.intelligence.trust import create_signed_manifest
from php_sentinel.models.intelligence_source import (
    IntelligenceSource,
    IntelligenceSourceChannel,
    IntelligenceSourceRegistry,
)
from php_sentinel.models.intelligence_trust import TrustedSigner, TrustStore
from php_sentinel.models.security_audit import SecurityAuditEventType

NOW = datetime(
    2026,
    10,
    24,
    12,
    0,
    tzinfo=UTC,
)

POLICY_URL = "https://updates.example.test/intel/stable/policy.json"
MANIFEST_URL = "https://updates.example.test/intel/stable/manifest.json"


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


def public_resolver(
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
            ("8.8.8.8", port),
        )
    ]


def peer_address(
    response,
):
    return "8.8.8.8"


def registry(
    *,
    allowed_signer: str,
) -> IntelligenceSourceRegistry:
    return IntelligenceSourceRegistry(
        sources=[
            IntelligenceSource(
                source_id="official",
                base_url="https://updates.example.test/intel/",
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


def signed_bundle(
    *,
    signer_id: str,
):
    private, public = key_pair()
    policy = default_policy()

    manifest = create_signed_manifest(
        policy=policy,
        signer_id=signer_id,
        private_key_b64=private,
        generation=5,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    return (
        json.dumps(
            policy.model_dump(mode="json"),
            sort_keys=True,
        ).encode("utf-8"),
        json.dumps(
            manifest.model_dump(mode="json"),
            sort_keys=True,
        ).encode("utf-8"),
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id=signer_id,
                    public_key_b64=public,
                )
            ]
        ),
    )


def client_for(
    *,
    policy_bytes: bytes,
    manifest_bytes: bytes,
):
    def handler(request):
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


def write_json(
    path,
    value,
) -> None:
    path.write_text(
        json.dumps(value),
        encoding="utf-8",
    )


def test_registry_stage_audit_retains_source_and_channel_provenance(
    tmp_path,
):
    policy_bytes, manifest_bytes, _ = signed_bundle(
        signer_id="policy-signer",
    )

    audit_path = tmp_path / "audit.jsonl"
    stage = tmp_path / "stage"

    with client_for(
        policy_bytes=policy_bytes,
        manifest_bytes=manifest_bytes,
    ) as client:
        metadata = stage_registry_bundle_from_registry(
            registry=registry(
                allowed_signer="policy-signer",
            ),
            source_id="official",
            channel="stable",
            staging_directory=stage,
            security_audit_path=audit_path,
            client=client,
            resolver=public_resolver,
            peer_address_getter=peer_address,
            now=NOW,
        )

    assert metadata.source_id == "official"
    assert metadata.channel == "stable"

    events = read_security_audit_events(audit_path)

    assert len(events) == 1
    assert events[0].event_type == SecurityAuditEventType.UPDATE_STAGED
    assert events[0].source_id == "official"
    assert events[0].channel == "stable"


def test_registry_verification_does_not_emit_success_before_source_signer_authorization(
    tmp_path,
):
    policy_bytes, manifest_bytes, trust_store = signed_bundle(
        signer_id="globally-trusted",
    )

    stage = tmp_path / "stage"

    with client_for(
        policy_bytes=policy_bytes,
        manifest_bytes=manifest_bytes,
    ) as client:
        stage_registry_bundle_from_registry(
            registry=registry(
                allowed_signer="different-source-signer",
            ),
            source_id="official",
            channel="stable",
            staging_directory=stage,
            client=client,
            resolver=public_resolver,
            peer_address_getter=peer_address,
            now=NOW,
        )

    trust_path = tmp_path / "trust.json"
    write_json(
        trust_path,
        trust_store.model_dump(mode="json"),
    )

    audit_path = tmp_path / "audit.jsonl"

    with pytest.raises(
        IntelligenceSourceRegistryError,
        match="not authorized",
    ):
        verify_registry_staged_bundle_from_registry(
            registry=registry(
                allowed_signer="different-source-signer",
            ),
            source_id="official",
            channel="stable",
            staging_directory=stage,
            trust_store_path=trust_path,
            lifecycle_state_path=(tmp_path / "lifecycle.json"),
            security_audit_path=audit_path,
            now=NOW,
        )

    assert read_security_audit_events(audit_path) == []


def test_registry_verification_emits_source_aware_success_after_full_authorization(
    tmp_path,
):
    policy_bytes, manifest_bytes, trust_store = signed_bundle(
        signer_id="policy-signer",
    )

    stage = tmp_path / "stage"

    with client_for(
        policy_bytes=policy_bytes,
        manifest_bytes=manifest_bytes,
    ) as client:
        stage_registry_bundle_from_registry(
            registry=registry(
                allowed_signer="policy-signer",
            ),
            source_id="official",
            channel="stable",
            staging_directory=stage,
            client=client,
            resolver=public_resolver,
            peer_address_getter=peer_address,
            now=NOW,
        )

    trust_path = tmp_path / "trust.json"
    write_json(
        trust_path,
        trust_store.model_dump(mode="json"),
    )

    audit_path = tmp_path / "audit.jsonl"

    candidate = verify_registry_staged_bundle_from_registry(
        registry=registry(
            allowed_signer="policy-signer",
        ),
        source_id="official",
        channel="stable",
        staging_directory=stage,
        trust_store_path=trust_path,
        lifecycle_state_path=(tmp_path / "lifecycle.json"),
        security_audit_path=audit_path,
        now=NOW,
    )

    assert candidate.manifest.signer_id == "policy-signer"

    events = read_security_audit_events(audit_path)

    assert len(events) == 1
    assert events[0].event_type == SecurityAuditEventType.UPDATE_VERIFIED
    assert events[0].source_id == "official"
    assert events[0].channel == "stable"
    assert events[0].signer_id == "policy-signer"
