from __future__ import annotations

import base64
import json
import socket
from datetime import UTC, datetime, timedelta

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from php_sentinel.intelligence.repository import default_policy
from php_sentinel.intelligence.security_audit import read_security_audit_events
from php_sentinel.intelligence.trust import create_signed_manifest
from php_sentinel.intelligence.update import (
    promote_verified_candidate,
    stage_remote_bundle,
    verify_staged_bundle,
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

POLICY_URL = "https://updates.example.test/policy.json"
MANIFEST_URL = "https://updates.example.test/manifest.json"


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


def fixture_data(tmp_path):
    private, public = key_pair()
    policy = default_policy()

    manifest = create_signed_manifest(
        policy=policy,
        signer_id="policy-signer",
        private_key_b64=private,
        generation=5,
        issued_at=NOW,
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

    trust_path = tmp_path / "trust.json"
    lifecycle_path = tmp_path / "lifecycle.json"

    trust_path.write_text(
        json.dumps(
            TrustStore(
                signers=[
                    TrustedSigner(
                        signer_id="policy-signer",
                        public_key_b64=public,
                    )
                ]
            ).model_dump(mode="json")
        ),
        encoding="utf-8",
    )

    return {
        "policy": policy,
        "policy_bytes": policy_bytes,
        "manifest_bytes": manifest_bytes,
        "trust_path": trust_path,
        "lifecycle_path": lifecycle_path,
    }


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


def stage_and_verify(
    *,
    tmp_path,
    data,
    audit_path,
):
    stage = tmp_path / "stage"

    with client_for(
        policy_bytes=data["policy_bytes"],
        manifest_bytes=data["manifest_bytes"],
    ) as client:
        stage_remote_bundle(
            policy_url=POLICY_URL,
            manifest_url=MANIFEST_URL,
            staging_directory=stage,
            security_audit_path=audit_path,
            client=client,
            resolver=public_resolver,
            peer_address_getter=peer_address,
            now=NOW,
        )

    candidate = verify_staged_bundle(
        staging_directory=stage,
        trust_store_path=data["trust_path"],
        lifecycle_state_path=data["lifecycle_path"],
        security_audit_path=audit_path,
        now=NOW,
    )

    return stage, candidate


def test_stage_verify_promote_emit_descriptive_events(
    tmp_path,
):
    data = fixture_data(tmp_path)
    audit_path = tmp_path / "audit.jsonl"

    _, candidate = stage_and_verify(
        tmp_path=tmp_path,
        data=data,
        audit_path=audit_path,
    )

    destination = promote_verified_candidate(
        candidate=candidate,
        verified_root=(tmp_path / "verified"),
        security_audit_path=audit_path,
    )

    events = read_security_audit_events(audit_path)

    assert [event.event_type for event in events] == [
        SecurityAuditEventType.UPDATE_STAGED,
        SecurityAuditEventType.UPDATE_VERIFIED,
        SecurityAuditEventType.UPDATE_PROMOTED,
    ]

    assert events[1].policy_id == data["policy"].policy_id
    assert events[1].signer_id == "policy-signer"
    assert events[1].generation == 5
    assert destination.is_dir()

    assert not data["lifecycle_path"].exists()


def test_idempotent_promotion_emits_existing_cache_reason(
    tmp_path,
):
    data = fixture_data(tmp_path)
    audit_path = tmp_path / "audit.jsonl"

    _, candidate = stage_and_verify(
        tmp_path=tmp_path,
        data=data,
        audit_path=audit_path,
    )

    first = promote_verified_candidate(
        candidate=candidate,
        verified_root=(tmp_path / "verified"),
        security_audit_path=audit_path,
    )

    second = promote_verified_candidate(
        candidate=candidate,
        verified_root=(tmp_path / "verified"),
        security_audit_path=audit_path,
    )

    assert first == second

    events = read_security_audit_events(audit_path)
    promoted = [
        event for event in events if event.event_type == SecurityAuditEventType.UPDATE_PROMOTED
    ]

    assert len(promoted) == 2
    assert promoted[0].reason_code == "new_cache_entry"
    assert promoted[1].reason_code == "existing_identical_cache"


def test_update_audit_failure_does_not_change_successful_pipeline(
    tmp_path,
):
    data = fixture_data(tmp_path)

    audit_target = tmp_path / "audit-target.jsonl"
    audit_target.write_text(
        "sentinel",
        encoding="utf-8",
    )

    audit_path = tmp_path / "audit.jsonl"
    audit_path.symlink_to(audit_target)

    stage = tmp_path / "stage"

    with client_for(
        policy_bytes=data["policy_bytes"],
        manifest_bytes=data["manifest_bytes"],
    ) as client:
        metadata = stage_remote_bundle(
            policy_url=POLICY_URL,
            manifest_url=MANIFEST_URL,
            staging_directory=stage,
            security_audit_path=audit_path,
            client=client,
            resolver=public_resolver,
            peer_address_getter=peer_address,
            now=NOW,
        )

    candidate = verify_staged_bundle(
        staging_directory=stage,
        trust_store_path=data["trust_path"],
        lifecycle_state_path=data["lifecycle_path"],
        security_audit_path=audit_path,
        now=NOW,
    )

    destination = promote_verified_candidate(
        candidate=candidate,
        verified_root=(tmp_path / "verified"),
        security_audit_path=audit_path,
    )

    assert metadata.policy_bytes > 0
    assert candidate.trust.trusted
    assert candidate.lifecycle.activatable
    assert destination.is_dir()
    assert not data["lifecycle_path"].exists()
    assert audit_target.read_text(encoding="utf-8") == "sentinel"
