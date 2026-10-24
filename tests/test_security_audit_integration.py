from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from php_sentinel.intelligence.activation import (
    activate_verified_intelligence_objects,
)
from php_sentinel.intelligence.registry_trust import (
    activate_signed_source_registry,
    create_signed_source_registry_manifest,
)
from php_sentinel.intelligence.repository import default_policy
from php_sentinel.intelligence.security_audit import read_security_audit_events
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


def write_json(
    path,
    value,
) -> None:
    path.write_text(
        json.dumps(value),
        encoding="utf-8",
    )


def test_intelligence_acceptance_emits_post_commit_audit_event(
    tmp_path,
):
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

    trust_path = tmp_path / "trust.json"
    state_path = tmp_path / "lifecycle.json"
    audit_path = tmp_path / "audit.jsonl"

    write_json(
        trust_path,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="policy-signer",
                    public_key_b64=public,
                )
            ]
        ).model_dump(mode="json"),
    )

    selection = activate_verified_intelligence_objects(
        policy=policy,
        manifest=manifest,
        trust_store_path=trust_path,
        lifecycle_state_path=state_path,
        security_audit_path=audit_path,
        now=NOW,
    )

    assert selection.policy.policy_id == policy.policy_id
    assert selection.trust.trusted
    assert selection.lifecycle.activatable
    assert state_path.exists()

    [event] = read_security_audit_events(audit_path)

    assert event.event_type == SecurityAuditEventType.INTELLIGENCE_ACTIVATION_ACCEPTED

    assert event.policy_id == policy.policy_id
    assert event.signer_id == "policy-signer"
    assert event.generation == 5
    assert event.trust_state == selection.trust.state.value
    assert event.lifecycle_state == selection.lifecycle.state.value


def test_registry_acceptance_emits_post_commit_audit_event(
    tmp_path,
):
    private, public = key_pair()

    registry = IntelligenceSourceRegistry(
        sources=[
            IntelligenceSource(
                source_id="official",
                base_url="https://updates.example.test/intel/",
                allowed_signer_ids=["policy-signer"],
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

    manifest = create_signed_source_registry_manifest(
        registry=registry,
        signer_id="registry-signer",
        private_key_b64=private,
        generation=5,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    registry_path = tmp_path / "registry.json"
    manifest_path = tmp_path / "registry-manifest.json"
    trust_path = tmp_path / "registry-trust.json"
    state_path = tmp_path / "registry-state.json"
    audit_path = tmp_path / "audit.jsonl"

    write_json(
        registry_path,
        registry.model_dump(mode="json"),
    )

    write_json(
        manifest_path,
        manifest.model_dump(mode="json"),
    )

    write_json(
        trust_path,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="registry-signer",
                    public_key_b64=public,
                )
            ]
        ).model_dump(mode="json"),
    )

    verified = activate_signed_source_registry(
        registry_path=registry_path,
        manifest_path=manifest_path,
        registry_trust_store_path=trust_path,
        registry_state_path=state_path,
        security_audit_path=audit_path,
        now=NOW,
    )

    assert verified.trust.trusted
    assert verified.lifecycle.activatable
    assert state_path.exists()

    [event] = read_security_audit_events(audit_path)

    assert event.event_type == SecurityAuditEventType.REGISTRY_ACTIVATION_ACCEPTED

    assert event.registry_id == manifest.registry_id
    assert event.signer_id == "registry-signer"
    assert event.generation == 5
    assert event.trust_state == verified.trust.state.value
    assert event.lifecycle_state == verified.lifecycle.state.value


def test_default_authority_activation_does_not_create_audit_file(
    tmp_path,
):
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

    trust_path = tmp_path / "trust.json"
    state_path = tmp_path / "lifecycle.json"
    audit_path = tmp_path / "audit.jsonl"

    write_json(
        trust_path,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="policy-signer",
                    public_key_b64=public,
                )
            ]
        ).model_dump(mode="json"),
    )

    selection = activate_verified_intelligence_objects(
        policy=policy,
        manifest=manifest,
        trust_store_path=trust_path,
        lifecycle_state_path=state_path,
        now=NOW,
    )

    assert selection.lifecycle.activatable
    assert state_path.exists()
    assert not audit_path.exists()


def test_intelligence_audit_failure_does_not_change_accepted_activation(
    tmp_path,
):
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

    trust_path = tmp_path / "trust.json"
    state_path = tmp_path / "lifecycle.json"

    audit_target = tmp_path / "audit-target.jsonl"
    audit_target.write_text(
        "sentinel",
        encoding="utf-8",
    )

    audit_path = tmp_path / "audit.jsonl"
    audit_path.symlink_to(audit_target)

    write_json(
        trust_path,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="policy-signer",
                    public_key_b64=public,
                )
            ]
        ).model_dump(mode="json"),
    )

    selection = activate_verified_intelligence_objects(
        policy=policy,
        manifest=manifest,
        trust_store_path=trust_path,
        lifecycle_state_path=state_path,
        security_audit_path=audit_path,
        now=NOW,
    )

    assert selection.trust.trusted
    assert selection.lifecycle.activatable
    assert state_path.exists()
    assert audit_target.read_text(encoding="utf-8") == "sentinel"


def test_registry_audit_failure_does_not_change_accepted_activation(
    tmp_path,
):
    private, public = key_pair()

    registry = IntelligenceSourceRegistry(
        sources=[
            IntelligenceSource(
                source_id="official",
                base_url="https://updates.example.test/intel/",
                allowed_signer_ids=["policy-signer"],
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

    manifest = create_signed_source_registry_manifest(
        registry=registry,
        signer_id="registry-signer",
        private_key_b64=private,
        generation=5,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    registry_path = tmp_path / "registry.json"
    manifest_path = tmp_path / "registry-manifest.json"
    trust_path = tmp_path / "registry-trust.json"
    state_path = tmp_path / "registry-state.json"

    audit_target = tmp_path / "audit-target.jsonl"
    audit_target.write_text(
        "sentinel",
        encoding="utf-8",
    )

    audit_path = tmp_path / "audit.jsonl"
    audit_path.symlink_to(audit_target)

    write_json(
        registry_path,
        registry.model_dump(mode="json"),
    )

    write_json(
        manifest_path,
        manifest.model_dump(mode="json"),
    )

    write_json(
        trust_path,
        TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="registry-signer",
                    public_key_b64=public,
                )
            ]
        ).model_dump(mode="json"),
    )

    verified = activate_signed_source_registry(
        registry_path=registry_path,
        manifest_path=manifest_path,
        registry_trust_store_path=trust_path,
        registry_state_path=state_path,
        security_audit_path=audit_path,
        now=NOW,
    )

    assert verified.trust.trusted
    assert verified.lifecycle.activatable
    assert state_path.exists()
    assert audit_target.read_text(encoding="utf-8") == "sentinel"
