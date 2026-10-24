import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from php_sentinel.intelligence.registry_trust import (
    SourceRegistryStateStorageError,
    SourceRegistryVerificationError,
    activate_signed_source_registry,
    canonical_source_registry_bytes,
    create_signed_source_registry_manifest,
    evaluate_source_registry_lifecycle,
    load_source_registry_state,
    record_accepted_source_registry,
    registry_manifest_signing_bytes,
    save_source_registry_state,
    source_registry_sha256,
    verify_signed_source_registry,
    verify_source_registry_manifest,
)
from php_sentinel.intelligence.repository import (
    default_policy,
)
from php_sentinel.intelligence.state_key import (
    authority_state_key_path_for_state,
    load_authority_state_key,
)
from php_sentinel.intelligence.trust import (
    create_signed_manifest,
    manifest_signing_bytes,
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
from php_sentinel.models.registry_trust import (
    SourceRegistryLifecycleState,
    SourceRegistryStateStore,
    SourceRegistryTrustState,
)

NOW = datetime(
    2026,
    10,
    23,
    18,
    0,
    tzinfo=UTC,
)


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


def registry():
    return IntelligenceSourceRegistry(
        sources=[
            IntelligenceSource(
                source_id="official",
                base_url=("https://updates.example.test/intel/"),
                allowed_signer_ids=["intelligence-signer"],
                channels=[
                    IntelligenceSourceChannel(
                        channel="stable",
                        policy_path=("stable/policy.json"),
                        manifest_path=("stable/manifest.json"),
                        minimum_generation=5,
                    )
                ],
            )
        ]
    )


def write_signed_registry(
    tmp_path,
    *,
    generation=5,
    signer_id="registry-signer",
    issued_at=NOW,
    expires_at=None,
):
    private_b64, public_b64 = key_material()

    source_registry = registry()

    manifest = create_signed_source_registry_manifest(
        registry=source_registry,
        signer_id=signer_id,
        private_key_b64=private_b64,
        generation=generation,
        issued_at=issued_at,
        expires_at=(expires_at or (issued_at + timedelta(days=10))),
    )

    registry_path = tmp_path / "registry.json"

    registry_path.write_text(
        json.dumps(source_registry.model_dump(mode="json")),
        encoding="utf-8",
    )

    manifest_path = tmp_path / "registry-manifest.json"

    manifest_path.write_text(
        json.dumps(manifest.model_dump(mode="json")),
        encoding="utf-8",
    )

    trust_store = TrustStore(
        signers=[
            TrustedSigner(
                signer_id=signer_id,
                public_key_b64=(public_b64),
            )
        ]
    )

    trust_path = tmp_path / "registry-trust.json"

    trust_path.write_text(
        json.dumps(trust_store.model_dump(mode="json")),
        encoding="utf-8",
    )

    return (
        source_registry,
        manifest,
        registry_path,
        manifest_path,
        trust_path,
        private_b64,
        public_b64,
    )


def test_registry_digest_is_canonical():
    first = registry()

    second = IntelligenceSourceRegistry.model_validate(
        json.loads(
            json.dumps(
                first.model_dump(mode="json"),
                sort_keys=False,
            )
        )
    )

    assert canonical_source_registry_bytes(first) == canonical_source_registry_bytes(second)

    assert source_registry_sha256(first) == source_registry_sha256(second)


def test_registry_signature_domain_is_distinct():
    registry_private, _ = key_material()

    manifest = create_signed_source_registry_manifest(
        registry=registry(),
        signer_id="same-signer",
        private_key_b64=(registry_private),
        generation=5,
        issued_at=NOW,
        expires_at=(NOW + timedelta(days=10)),
    )

    policy = default_policy()

    policy_manifest = create_signed_manifest(
        policy=policy,
        signer_id="same-signer",
        private_key_b64=registry_private,
        issued_at=NOW,
        generation=5,
        expires_at=(NOW + timedelta(days=10)),
    )

    assert registry_manifest_signing_bytes(manifest) != manifest_signing_bytes(policy_manifest)


def test_valid_signed_registry_is_trusted(
    tmp_path,
):
    (
        source_registry,
        manifest,
        _,
        _,
        _,
        _,
        public_b64,
    ) = write_signed_registry(tmp_path)

    decision = verify_source_registry_manifest(
        registry=source_registry,
        manifest=manifest,
        trust_store=TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="registry-signer",
                    public_key_b64=(public_b64),
                )
            ]
        ),
    )

    assert decision.trusted is True
    assert decision.state == SourceRegistryTrustState.TRUSTED


def test_unknown_registry_signer_fails_closed(
    tmp_path,
):
    (
        source_registry,
        manifest,
        _,
        _,
        _,
        _,
        _,
    ) = write_signed_registry(tmp_path)

    decision = verify_source_registry_manifest(
        registry=source_registry,
        manifest=manifest,
        trust_store=TrustStore(),
    )

    assert decision.trusted is False
    assert decision.state == SourceRegistryTrustState.UNKNOWN_SIGNER


def test_registry_digest_tampering_is_rejected(
    tmp_path,
):
    (
        source_registry,
        manifest,
        _,
        _,
        _,
        _,
        public_b64,
    ) = write_signed_registry(tmp_path)

    tampered = source_registry.model_copy(deep=True)

    tampered.sources[0].enabled = False

    decision = verify_source_registry_manifest(
        registry=tampered,
        manifest=manifest,
        trust_store=TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="registry-signer",
                    public_key_b64=(public_b64),
                )
            ]
        ),
    )

    assert decision.trusted is False
    assert decision.state == SourceRegistryTrustState.DIGEST_MISMATCH


def test_expired_registry_is_rejected(
    tmp_path,
):
    (
        _,
        _,
        registry_path,
        manifest_path,
        trust_path,
        _,
        _,
    ) = write_signed_registry(
        tmp_path,
        issued_at=(NOW - timedelta(days=10)),
        expires_at=(NOW - timedelta(days=1)),
    )

    with pytest.raises(
        SourceRegistryVerificationError,
        match="expired",
    ):
        verify_signed_source_registry(
            registry_path=registry_path,
            manifest_path=manifest_path,
            registry_trust_store_path=(trust_path),
            registry_state_path=(tmp_path / "registry-state.json"),
            now=NOW,
        )


def test_registry_rollback_is_rejected(
    tmp_path,
):
    (
        source_registry,
        manifest,
        registry_path,
        manifest_path,
        trust_path,
        _,
        _,
    ) = write_signed_registry(
        tmp_path,
        generation=4,
    )

    state_path = tmp_path / "registry-state.json"

    from php_sentinel.models.registry_trust import (
        SourceRegistryStateRecord,
    )

    state = SourceRegistryStateStore(
        records={
            manifest.registry_id: (
                SourceRegistryStateRecord(
                    generation=5,
                    registry_sha256=(source_registry_sha256(source_registry)),
                    signer_id=("registry-signer"),
                    accepted_at=NOW,
                )
            )
        }
    )

    from php_sentinel.intelligence.registry_trust import (
        save_source_registry_state,
    )

    save_source_registry_state(
        state_path,
        state,
    )

    with pytest.raises(
        SourceRegistryVerificationError,
        match="rollback_detected",
    ):
        verify_signed_source_registry(
            registry_path=registry_path,
            manifest_path=manifest_path,
            registry_trust_store_path=(trust_path),
            registry_state_path=(state_path),
            now=NOW,
        )


def test_same_generation_different_registry_is_replay(
    tmp_path,
):
    (
        source_registry,
        manifest,
        _,
        _,
        _,
        _,
        public_b64,
    ) = write_signed_registry(
        tmp_path,
        generation=5,
    )

    trust = verify_source_registry_manifest(
        registry=source_registry,
        manifest=manifest,
        trust_store=TrustStore(
            signers=[
                TrustedSigner(
                    signer_id="registry-signer",
                    public_key_b64=(public_b64),
                )
            ]
        ),
    )

    from php_sentinel.models.registry_trust import (
        SourceRegistryStateRecord,
    )

    state = SourceRegistryStateStore(
        records={
            manifest.registry_id: (
                SourceRegistryStateRecord(
                    generation=5,
                    registry_sha256=("0" * 64),
                    signer_id=("registry-signer"),
                    accepted_at=NOW,
                )
            )
        }
    )

    lifecycle = evaluate_source_registry_lifecycle(
        registry=source_registry,
        manifest=manifest,
        trust=trust,
        state=state,
        now=NOW,
    )

    assert lifecycle.activatable is False
    assert lifecycle.state == SourceRegistryLifecycleState.REPLAY_DETECTED


def test_registry_verification_does_not_advance_state(
    tmp_path,
):
    (
        _,
        _,
        registry_path,
        manifest_path,
        trust_path,
        _,
        _,
    ) = write_signed_registry(
        tmp_path,
        generation=5,
    )

    state_path = tmp_path / "registry-state.json"

    verified = verify_signed_source_registry(
        registry_path=registry_path,
        manifest_path=manifest_path,
        registry_trust_store_path=(trust_path),
        registry_state_path=(state_path),
        now=NOW,
    )

    assert verified.lifecycle.activatable is True
    assert not state_path.exists()
    assert not authority_state_key_path_for_state(state_path).exists()


def test_registry_activation_records_generation(
    tmp_path,
):
    (
        _,
        _,
        registry_path,
        manifest_path,
        trust_path,
        _,
        _,
    ) = write_signed_registry(
        tmp_path,
        generation=5,
    )

    state_path = tmp_path / "registry-state.json"

    verified = activate_signed_source_registry(
        registry_path=registry_path,
        manifest_path=manifest_path,
        registry_trust_store_path=(trust_path),
        registry_state_path=(state_path),
        now=NOW,
    )

    authority_key_path = authority_state_key_path_for_state(state_path)
    authority_key = load_authority_state_key(authority_key_path)

    state = load_source_registry_state(
        state_path,
        authority_key=authority_key,
        require_authenticated=True,
    )

    record = state.records[verified.manifest.registry_id]

    assert record.generation == 5

    assert record.registry_sha256 == verified.trust.registry_sha256


def test_registry_state_commit_detects_concurrent_change(
    tmp_path,
):
    (
        source_registry,
        manifest,
        registry_path,
        manifest_path,
        trust_path,
        _,
        _,
    ) = write_signed_registry(
        tmp_path,
        generation=5,
    )

    state_path = tmp_path / "registry-state.json"

    verified = verify_signed_source_registry(
        registry_path=registry_path,
        manifest_path=manifest_path,
        registry_trust_store_path=(trust_path),
        registry_state_path=(state_path),
        now=NOW,
    )

    from php_sentinel.intelligence.registry_trust import (
        save_source_registry_state,
    )
    from php_sentinel.models.registry_trust import (
        SourceRegistryStateRecord,
    )

    changed = SourceRegistryStateStore(
        records={
            manifest.registry_id: (
                SourceRegistryStateRecord(
                    generation=4,
                    registry_sha256=(source_registry_sha256(source_registry)),
                    signer_id=("registry-signer"),
                    accepted_at=NOW,
                )
            )
        }
    )

    save_source_registry_state(
        state_path,
        changed,
    )

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="changed between",
    ):
        record_accepted_source_registry(
            path=state_path,
            registry=verified.registry,
            manifest=verified.manifest,
            lifecycle=verified.lifecycle,
            expected_state=(verified.state_snapshot),
            now=NOW,
        )


def test_source_registry_manifest_rejects_noncanonical_signer_identity():
    import pytest

    registry = IntelligenceSourceRegistry()
    private_key, _ = key_material()

    with pytest.raises(ValueError):
        create_signed_source_registry_manifest(
            registry=registry,
            signer_id="registry|signer",
            private_key_b64=private_key,
            generation=1,
            issued_at=NOW,
            expires_at=(NOW + timedelta(days=1)),
        )


def test_source_registry_state_read_rejects_symlink(
    tmp_path,
):
    from php_sentinel.intelligence.registry_trust import (
        SourceRegistryStateStorageError,
        load_source_registry_state,
    )
    from php_sentinel.models.registry_trust import (
        SourceRegistryStateStore,
    )

    outside = tmp_path / "outside-registry-state.json"
    outside.write_text(
        json.dumps(SourceRegistryStateStore().model_dump(mode="json")),
        encoding="utf-8",
    )

    state_path = tmp_path / "registry-state.json"
    state_path.symlink_to(outside)

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="symbolic link",
    ):
        load_source_registry_state(state_path)


def test_source_registry_state_read_rejects_non_regular_file(
    tmp_path,
):
    from php_sentinel.intelligence.registry_trust import (
        SourceRegistryStateStorageError,
        load_source_registry_state,
    )

    state_path = tmp_path / "registry-state.json"
    state_path.mkdir()

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="not a regular file",
    ):
        load_source_registry_state(state_path)


def test_source_registry_state_write_rejects_symlinked_temporary_file(
    tmp_path,
):
    from php_sentinel.intelligence.registry_trust import (
        SourceRegistryStateStorageError,
        save_source_registry_state,
    )
    from php_sentinel.models.registry_trust import (
        SourceRegistryStateStore,
    )

    state_path = tmp_path / "registry-state.json"
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")

    outside = tmp_path / "outside.json"
    outside.write_text(
        "do-not-modify",
        encoding="utf-8",
    )

    temporary.symlink_to(outside)

    with pytest.raises(
        SourceRegistryStateStorageError,
        match="durably persist",
    ):
        save_source_registry_state(
            state_path,
            SourceRegistryStateStore(),
        )

    assert outside.read_text(encoding="utf-8") == "do-not-modify"


def test_source_registry_state_write_remains_bound_to_open_directory(
    tmp_path,
):
    import php_sentinel.intelligence.registry_trust as registry_module
    from php_sentinel.intelligence.lifecycle import lifecycle_state_lock
    from php_sentinel.intelligence.registry_trust import (
        load_source_registry_state,
    )
    from php_sentinel.models.registry_trust import (
        SourceRegistryStateStore,
    )

    state_directory = tmp_path / "registry-state"
    state_path = state_directory / "registry.json"

    replacement_payload = "replacement-registry-state"

    with lifecycle_state_lock(state_path) as anchor:
        displaced_directory = tmp_path / "registry-state-original"

        state_directory.rename(displaced_directory)
        state_directory.mkdir()

        replacement_state = state_directory / "registry.json"
        replacement_state.write_text(
            replacement_payload,
            encoding="utf-8",
        )

        registry_module._save_source_registry_state_unlocked(
            state_path,
            SourceRegistryStateStore(),
            _anchor=anchor,
        )

    persisted_original = displaced_directory / "registry.json"

    assert persisted_original.exists()
    assert replacement_state.read_text(encoding="utf-8") == replacement_payload

    loaded = load_source_registry_state(persisted_original)

    assert loaded == SourceRegistryStateStore()


def test_registry_activation_rejects_unsigned_legacy_state(
    tmp_path,
):
    (
        _,
        _,
        registry_path,
        manifest_path,
        trust_path,
        _,
        _,
    ) = write_signed_registry(
        tmp_path,
        generation=5,
    )

    state_path = tmp_path / "registry-state.json"

    save_source_registry_state(
        state_path,
        SourceRegistryStateStore(),
    )

    with pytest.raises(
        SourceRegistryVerificationError,
        match="not an authenticated authority-state envelope",
    ):
        activate_signed_source_registry(
            registry_path=registry_path,
            manifest_path=manifest_path,
            registry_trust_store_path=trust_path,
            registry_state_path=state_path,
            now=NOW,
        )
