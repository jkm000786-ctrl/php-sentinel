import base64
import json
import shutil
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from pydantic import ValidationError

from php_sentinel.intelligence.activation import (
    IntelligenceActivationError,
)
from php_sentinel.intelligence.lifecycle import (
    save_lifecycle_state,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    policy_sha256,
)
from php_sentinel.intelligence.state_key import (
    authority_state_key_path_for_state,
    load_or_create_authority_state_key,
)
from php_sentinel.intelligence.trust import (
    create_signed_manifest,
)
from php_sentinel.intelligence.update import (
    IntelligenceUpdatePromotionError,
    IntelligenceVerifiedCacheError,
    VerifiedUpdateCandidate,
    activate_cached_intelligence,
    discover_verified_cache,
    promote_verified_candidate,
    select_verified_cache_candidate,
)
from php_sentinel.models.intelligence_lifecycle import (
    IntelligenceLifecycleDecision,
    IntelligenceLifecycleState,
    LifecycleStateRecord,
    LifecycleStateStore,
)
from php_sentinel.models.intelligence_trust import (
    IntelligenceTrustDecision,
    IntelligenceTrustState,
    TrustedSigner,
    TrustStore,
)
from php_sentinel.models.intelligence_update import (
    IntelligenceUpdateStageMetadata,
    IntelligenceUpdateVerificationMetadata,
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


def create_cached_entry(
    tmp_path,
    *,
    generation,
    signer_id="cache-signer",
    private_b64=None,
    public_b64=None,
):
    if private_b64 is None or public_b64 is None:
        (
            private_b64,
            public_b64,
        ) = key_material()

    policy = default_policy().model_copy(deep=True)

    digest = policy_sha256(policy)

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

    trust = IntelligenceTrustDecision(
        state=IntelligenceTrustState.TRUSTED,
        trusted=True,
        policy_id=policy.policy_id,
        policy_sha256=digest,
        signer_id=signer_id,
        algorithm="ed25519",
    )

    lifecycle = IntelligenceLifecycleDecision(
        state=(IntelligenceLifecycleState.CURRENT),
        activatable=True,
        policy_id=(policy.policy_id),
        policy_sha256=digest,
        generation=generation,
        issued_at=(manifest.issued_at),
        expires_at=(manifest.expires_at),
        signer_id=signer_id,
    )

    stage = tmp_path / f"stage-{generation}"

    stage.mkdir(
        parents=True,
        exist_ok=True,
    )

    policy_bytes = json.dumps(
        policy.model_dump(mode="json"),
        sort_keys=True,
    ).encode("utf-8")

    manifest_bytes = json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
    ).encode("utf-8")

    (stage / "policy.json").write_bytes(policy_bytes)

    (stage / "manifest.json").write_bytes(manifest_bytes)

    import hashlib

    stage_metadata = IntelligenceUpdateStageMetadata(
        policy_url=("https://updates.example.test/policy.json"),
        manifest_url=("https://updates.example.test/manifest.json"),
        fetched_at=NOW,
        policy_transport_sha256=(hashlib.sha256(policy_bytes).hexdigest()),
        manifest_transport_sha256=(hashlib.sha256(manifest_bytes).hexdigest()),
        policy_bytes=len(policy_bytes),
        manifest_bytes=len(manifest_bytes),
    )

    (stage / "stage-metadata.json").write_text(
        json.dumps(stage_metadata.model_dump(mode="json")),
        encoding="utf-8",
    )

    verification = IntelligenceUpdateVerificationMetadata(
        policy_id=(policy.policy_id),
        policy_sha256=digest,
        manifest_version=(manifest.manifest_version),
        generation=generation,
        signer_id=signer_id,
        trust_state="trusted",
        lifecycle_state="current",
        trusted=True,
        activatable=True,
        verified_at=NOW,
        source_policy_url=(stage_metadata.policy_url),
        source_manifest_url=(stage_metadata.manifest_url),
        staged_policy_transport_sha256=(stage_metadata.policy_transport_sha256),
        staged_manifest_transport_sha256=(stage_metadata.manifest_transport_sha256),
    )

    candidate = VerifiedUpdateCandidate(
        policy=policy,
        manifest=manifest,
        trust=trust,
        lifecycle=lifecycle,
        state_snapshot=(LifecycleStateStore()),
        stage_directory=stage,
        stage_metadata=(stage_metadata),
        verification_metadata=(verification),
        _capability=(
            __import__(
                "php_sentinel.intelligence.update",
                fromlist=["_UPDATE_CAPABILITY"],
            )._UPDATE_CAPABILITY
        ),
    )

    verified_root = tmp_path / "verified"

    destination = promote_verified_candidate(
        candidate=candidate,
        verified_root=(verified_root),
    )

    trust_path = tmp_path / "trust.json"

    trust_path.write_text(
        json.dumps(trust_store.model_dump(mode="json")),
        encoding="utf-8",
    )

    return (
        policy,
        manifest,
        destination,
        verified_root,
        trust_path,
        private_b64,
        public_b64,
    )


def test_cache_discovery_does_not_report_trust_authority(
    tmp_path,
):
    (
        policy,
        _,
        destination,
        verified_root,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    entries = discover_verified_cache(verified_root)

    assert len(entries) == 1
    assert entries[0].path == str(destination)
    assert entries[0].policy_id == policy.policy_id

    dumped = entries[0].model_dump()

    assert "trusted" not in dumped
    assert "activatable" not in dumped


def test_highest_generation_is_selected(
    tmp_path,
):
    private_b64, public_b64 = key_material()

    create_cached_entry(
        tmp_path,
        generation=5,
        private_b64=private_b64,
        public_b64=public_b64,
    )

    create_cached_entry(
        tmp_path,
        generation=7,
        private_b64=private_b64,
        public_b64=public_b64,
    )

    selected = select_verified_cache_candidate(tmp_path / "verified")

    assert selected.generation == 7


def test_equivalent_duplicate_is_deterministic(
    tmp_path,
):
    (
        _,
        _,
        destination,
        verified_root,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    duplicate = verified_root / "duplicate-equivalent"

    shutil.copytree(
        destination,
        duplicate,
    )

    entries = discover_verified_cache(verified_root)

    assert len(entries) == 2

    selected = select_verified_cache_candidate(verified_root)

    assert selected.path == min(
        str(destination),
        str(duplicate),
    )


def test_conflicting_same_generation_fails_closed(
    tmp_path,
):
    (
        _,
        _,
        destination,
        verified_root,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    conflict = verified_root / "duplicate-conflict"

    shutil.copytree(
        destination,
        conflict,
    )

    manifest_path = conflict / "manifest.json"

    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Keep valid model shape and policy identity while making the
    # actual cached bundle bytes different.
    data["signature_b64"] = base64.b64encode(b"x" * 64).decode("ascii")

    manifest_path.write_text(
        json.dumps(
            data,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match=("Verified cache descriptive metadata is inconsistent|Conflicting verified-cache"),
    ):
        discover_verified_cache(verified_root)


def test_policy_corruption_is_rejected(
    tmp_path,
):
    (
        _,
        _,
        destination,
        _,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    (destination / "policy.json").write_text(
        "{not-json",
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match="invalid policy/manifest",
    ):
        discover_verified_cache(destination.parent)


def test_verification_metadata_is_not_authority(
    tmp_path,
):
    (
        _,
        _,
        destination,
        _,
        trust_path,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    # Descriptive metadata still claims prior verification.
    metadata = json.loads((destination / "verification.json").read_text(encoding="utf-8"))

    assert metadata["trusted"] is True
    assert metadata["activatable"] is True

    # But current LOCAL trust authority no longer trusts the signer.
    trust_path.write_text(
        json.dumps(TrustStore().model_dump(mode="json")),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceActivationError,
        match="unknown_signer",
    ):
        activate_cached_intelligence(
            cache_directory=(destination),
            trust_store_path=(trust_path),
            lifecycle_state_path=(tmp_path / "lifecycle.json"),
            now=NOW,
        )


def test_activation_rereads_lifecycle_and_blocks_rollback(
    tmp_path,
):
    (
        policy,
        _,
        destination,
        _,
        trust_path,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    state_path = tmp_path / "lifecycle.json"

    authority_key = load_or_create_authority_state_key(
        authority_state_key_path_for_state(state_path)
    )

    save_lifecycle_state(
        state_path,
        LifecycleStateStore(
            records={
                policy.policy_id: (
                    LifecycleStateRecord(
                        generation=6,
                        policy_sha256=(policy_sha256(policy)),
                        signer_id=("cache-signer"),
                        accepted_at=NOW,
                    )
                )
            }
        ),
        authority_key=authority_key,
    )

    with pytest.raises(
        IntelligenceActivationError,
        match="rollback_detected",
    ):
        activate_cached_intelligence(
            cache_directory=(destination),
            trust_store_path=(trust_path),
            lifecycle_state_path=(state_path),
            now=NOW,
        )


def test_metadata_identity_tampering_is_rejected(
    tmp_path,
):
    (
        _,
        _,
        destination,
        _,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    path = destination / "verification.json"

    metadata = json.loads(path.read_text(encoding="utf-8"))

    metadata["generation"] = 999

    path.write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match="metadata is inconsistent",
    ):
        discover_verified_cache(destination.parent)


@pytest.mark.parametrize(
    "field",
    [
        "staged_policy_transport_sha256",
        "staged_manifest_transport_sha256",
    ],
)
def test_cached_transport_digest_metadata_tampering_is_rejected(
    tmp_path,
    field,
):
    (
        _,
        _,
        destination,
        _,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    path = destination / "verification.json"
    metadata = json.loads(path.read_text(encoding="utf-8"))

    metadata[field] = "0" * 64

    path.write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match="metadata is inconsistent",
    ):
        discover_verified_cache(destination.parent)


def test_cache_entry_exposes_descriptive_source_transport_provenance(
    tmp_path,
):
    (
        _,
        _,
        destination,
        verified_root,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    [entry] = discover_verified_cache(verified_root)

    metadata = json.loads((destination / "verification.json").read_text(encoding="utf-8"))

    assert entry.source_policy_url == metadata["source_policy_url"]
    assert entry.source_manifest_url == metadata["source_manifest_url"]
    assert entry.staged_policy_transport_sha256 == metadata["staged_policy_transport_sha256"]
    assert entry.staged_manifest_transport_sha256 == metadata["staged_manifest_transport_sha256"]


@pytest.mark.parametrize(
    "policy_id",
    [
        "../escape",
        "../../outside",
        "/absolute",
        "nested/name",
        ".",
        "..",
        "name with spaces",
        "a" * 129,
    ],
)
def test_policy_id_rejects_filesystem_ambiguous_identity(
    policy_id,
):
    policy = default_policy()

    data = policy.model_dump(mode="json")
    data["policy_id"] = policy_id

    with pytest.raises(ValidationError):
        policy.__class__.model_validate(data)


@pytest.mark.parametrize(
    "policy_id",
    [
        "safe-policy",
        "safe_policy.v1",
        "php-2026-10-critical",
    ],
)
def test_policy_id_accepts_canonical_identity(
    policy_id,
):
    policy = default_policy()

    data = policy.model_dump(mode="json")
    data["policy_id"] = policy_id

    validated = policy.__class__.model_validate(data)

    assert validated.policy_id == policy_id


def test_verified_cache_promotion_returns_path_under_resolved_root(
    tmp_path,
):
    (
        _,
        _,
        destination,
        verified_root,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    assert destination.parent == verified_root.resolve()
    assert destination.is_relative_to(verified_root.resolve())


def test_promotion_rejects_symlink_cache_destination(
    tmp_path,
):
    (
        _,
        _,
        destination,
        _,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    outside = tmp_path / "outside"
    outside.mkdir()

    shutil.rmtree(destination)

    destination.symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(
        IntelligenceUpdatePromotionError,
        match="symbolic link",
    ):
        create_cached_entry(
            tmp_path,
            generation=5,
        )


def test_promotion_rejects_existing_non_directory_cache_destination(
    tmp_path,
):
    (
        _,
        _,
        destination,
        _,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    shutil.rmtree(destination)
    destination.write_text(
        "not-a-directory",
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceUpdatePromotionError,
        match="not a directory",
    ):
        create_cached_entry(
            tmp_path,
            generation=5,
        )


def test_discovery_ignores_symlinked_cache_entry_directory(
    tmp_path,
):
    (
        _,
        _,
        destination,
        verified_root,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    symlinked = verified_root / "symlinked-entry"
    symlinked.symlink_to(
        destination,
        target_is_directory=True,
    )

    entries = discover_verified_cache(verified_root)

    assert len(entries) == 1
    assert entries[0].path == str(destination.resolve())


@pytest.mark.parametrize(
    "filename",
    [
        "policy.json",
        "manifest.json",
        "verification.json",
    ],
)
def test_cache_inspection_rejects_symlinked_artifact(
    tmp_path,
    filename,
):
    (
        _,
        _,
        destination,
        _,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    artifact = destination / filename
    outside = tmp_path / f"outside-{filename}"
    outside.write_bytes(artifact.read_bytes())

    artifact.unlink()
    artifact.symlink_to(outside)

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match="symbolic link",
    ):
        discover_verified_cache(destination.parent)


@pytest.mark.parametrize(
    "filename",
    [
        "policy.json",
        "manifest.json",
        "verification.json",
    ],
)
def test_cache_inspection_rejects_non_regular_artifact(
    tmp_path,
    filename,
):
    (
        _,
        _,
        destination,
        _,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    artifact = destination / filename
    artifact.unlink()
    artifact.mkdir()

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match="not a regular file|missing or cannot be resolved",
    ):
        discover_verified_cache(destination.parent)


def test_activation_rejects_symlinked_policy_before_authoritative_activation(
    tmp_path,
):
    (
        _,
        _,
        destination,
        _,
        trust_path,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    policy = destination / "policy.json"
    outside = tmp_path / "outside-policy.json"
    outside.write_bytes(policy.read_bytes())

    policy.unlink()
    policy.symlink_to(outside)

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match="symbolic link",
    ):
        activate_cached_intelligence(
            cache_directory=destination,
            trust_store_path=trust_path,
            lifecycle_state_path=(tmp_path / "lifecycle.json"),
            now=NOW,
        )


def test_promotion_rejects_existing_symlinked_policy_artifact(
    tmp_path,
):
    (
        _,
        _,
        destination,
        _,
        _,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    policy = destination / "policy.json"
    outside = tmp_path / "outside-policy.json"
    outside.write_bytes(policy.read_bytes())

    policy.unlink()
    policy.symlink_to(outside)

    with pytest.raises(
        IntelligenceUpdatePromotionError,
        match="artifacts could not be read safely",
    ):
        create_cached_entry(
            tmp_path,
            generation=5,
        )


def test_cached_activation_uses_exact_securely_loaded_objects(
    tmp_path,
    monkeypatch,
):
    (
        _,
        _,
        destination,
        _,
        trust_path,
        _,
        _,
    ) = create_cached_entry(
        tmp_path,
        generation=5,
    )

    import php_sentinel.intelligence.update as update_module

    real_activate = update_module.activate_verified_intelligence_objects

    def replace_cache_path_then_activate(
        *,
        policy,
        manifest,
        **kwargs,
    ):
        cached_policy = destination / "policy.json"
        replacement = tmp_path / "replacement-policy.json"

        replacement.write_text(
            "{not-json",
            encoding="utf-8",
        )

        cached_policy.unlink()
        cached_policy.symlink_to(replacement)

        return real_activate(
            policy=policy,
            manifest=manifest,
            **kwargs,
        )

    monkeypatch.setattr(
        update_module,
        "activate_verified_intelligence_objects",
        replace_cache_path_then_activate,
    )

    selection = activate_cached_intelligence(
        cache_directory=destination,
        trust_store_path=trust_path,
        lifecycle_state_path=(tmp_path / "lifecycle.json"),
        now=NOW,
    )

    assert selection.policy.policy_id == default_policy().policy_id


def test_oversized_verified_cache_artifact_fails_closed(
    tmp_path,
):
    from php_sentinel.intelligence.update import (
        VERIFIED_CACHE_ARTIFACT_MAX_BYTES,
        IntelligenceVerifiedCacheError,
        inspect_verified_cache_entry,
    )

    entry = tmp_path / "entry"
    entry.mkdir()

    (entry / "policy.json").write_bytes(b"{" + (b"x" * VERIFIED_CACHE_ARTIFACT_MAX_BYTES))
    (entry / "manifest.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (entry / "verification.json").write_text(
        "{}",
        encoding="utf-8",
    )

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match="maximum allowed size",
    ):
        inspect_verified_cache_entry(entry)


def test_verified_cache_discovery_rejects_excessive_entry_count(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.update as update_module
    from php_sentinel.intelligence.update import (
        IntelligenceVerifiedCacheError,
        discover_verified_cache,
    )

    monkeypatch.setattr(
        update_module,
        "VERIFIED_CACHE_MAX_ENTRIES",
        3,
    )

    root = tmp_path / "verified"
    root.mkdir()

    for index in range(4):
        (root / f"entry-{index}").mkdir()

    with pytest.raises(
        IntelligenceVerifiedCacheError,
        match="too many entries",
    ):
        discover_verified_cache(root)


def test_cache_inspection_fails_closed_when_platform_descriptor_security_is_missing(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.update as update_module
    from php_sentinel.intelligence.platform_security import (
        PlatformSecurityCapabilityError,
    )

    entry = tmp_path / "cache-entry"
    entry.mkdir()

    def deny(
        *,
        operation,
    ):
        raise PlatformSecurityCapabilityError(f"{operation} unavailable.")

    monkeypatch.setattr(
        update_module,
        "require_verified_cache_descriptor_access",
        deny,
    )

    with pytest.raises(
        update_module.IntelligenceVerifiedCacheError,
        match="cannot provide the required descriptor security semantics",
    ):
        update_module.inspect_verified_cache_entry(entry)


def test_verified_cache_discovery_rejects_excessive_raw_entry_count(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.update as update_module

    monkeypatch.setattr(
        update_module,
        "VERIFIED_CACHE_MAX_DIRECTORY_ENTRIES",
        3,
    )

    root = tmp_path / "verified"
    root.mkdir()

    for index in range(4):
        (root / f".ignored-{index}").write_text(
            "noise",
            encoding="utf-8",
        )

    with pytest.raises(
        update_module.IntelligenceVerifiedCacheError,
        match="too many filesystem entries",
    ):
        update_module.discover_verified_cache(root)
