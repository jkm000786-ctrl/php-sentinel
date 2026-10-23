from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from php_sentinel.intelligence.delegation import (
    resolve_authorized_predecessor_evidence,
    resolve_verified_delegation_revocations,
    signer_delegation_revocation_sha256,
)
from php_sentinel.intelligence.lifecycle import (
    lifecycle_state_lock,
)
from php_sentinel.intelligence.source_registry import (
    IntelligenceSourceRegistryError,
    activate_registry_cached_intelligence_from_registry,
    stage_registry_bundle_from_registry,
    verify_registry_staged_bundle_from_registry,
)
from php_sentinel.intelligence.trust import load_trust_store
from php_sentinel.models.intelligence_lifecycle import (
    DelegationHistoryRecord,
    DelegationRevocationHistoryRecord,
)
from php_sentinel.models.intelligence_source import (
    IntelligenceSourceRegistry,
)
from php_sentinel.models.intelligence_trust import TrustStore
from php_sentinel.models.registry_trust import (
    SourceRegistryLifecycleDecision,
    SourceRegistryLifecycleState,
    SourceRegistryManifest,
    SourceRegistryStateRecord,
    SourceRegistryStateStore,
    SourceRegistryTrustDecision,
    SourceRegistryTrustState,
)

REGISTRY_SIGNATURE_DOMAIN_V1 = b"PHP-SENTINEL-SOURCE-REGISTRY-MANIFEST-V1\x00"

ED25519_PRIVATE_KEY_BYTES = 32
ED25519_PUBLIC_KEY_BYTES = 32

REGISTRY_STATE_DIRECTORY_MODE = 0o700
REGISTRY_STATE_FILE_MODE = 0o600

DEFAULT_REGISTRY_STATE_PATH = (
    Path.home() / ".local" / "state" / "php-sentinel" / "source-registry-lifecycle.json"
)


class SourceRegistryVerificationError(IntelligenceSourceRegistryError):
    """Raised when signed source-registry verification fails."""


class SourceRegistryStateStorageError(SourceRegistryVerificationError):
    """Raised when source-registry rollback state cannot be handled safely."""


_REGISTRY_CAPABILITY = object()


class VerifiedSourceRegistry:
    """
    Verified registry capability.

    This proves registry signature + lifecycle checks for the current
    verification operation. It does not create intelligence-policy trust.
    """

    __slots__ = (
        "lifecycle",
        "manifest",
        "registry",
        "state_snapshot",
        "trust",
    )

    def __init__(
        self,
        *,
        registry: IntelligenceSourceRegistry,
        manifest: SourceRegistryManifest,
        trust: SourceRegistryTrustDecision,
        lifecycle: SourceRegistryLifecycleDecision,
        state_snapshot: SourceRegistryStateStore,
        _capability: object | None = None,
    ) -> None:
        if _capability is not _REGISTRY_CAPABILITY:
            raise TypeError("VerifiedSourceRegistry cannot be constructed directly.")

        if not trust.trusted:
            raise ValueError("Verified source registry requires trusted signature state.")

        if not lifecycle.activatable:
            raise ValueError("Verified source registry requires activatable lifecycle.")

        self.registry = registry
        self.manifest = manifest
        self.trust = trust
        self.lifecycle = lifecycle
        self.state_snapshot = state_snapshot


def canonical_source_registry_bytes(
    registry: IntelligenceSourceRegistry,
) -> bytes:
    return json.dumps(
        registry.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def source_registry_sha256(
    registry: IntelligenceSourceRegistry,
) -> str:
    return hashlib.sha256(canonical_source_registry_bytes(registry)).hexdigest()


def registry_manifest_signing_payload(
    manifest: SourceRegistryManifest,
) -> dict[str, object]:
    return {
        "manifest_version": manifest.manifest_version,
        "registry_id": manifest.registry_id,
        "registry_sha256": manifest.registry_sha256,
        "generation": manifest.generation,
        "issued_at": manifest.issued_at.isoformat(),
        "expires_at": manifest.expires_at.isoformat(),
        "signer_id": manifest.signer_id,
        "algorithm": manifest.algorithm,
    }


def registry_manifest_signing_bytes(
    manifest: SourceRegistryManifest,
) -> bytes:
    canonical = json.dumps(
        registry_manifest_signing_payload(manifest),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return REGISTRY_SIGNATURE_DOMAIN_V1 + canonical


def create_signed_source_registry_manifest(
    *,
    registry: IntelligenceSourceRegistry,
    signer_id: str,
    private_key_b64: str,
    generation: int,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    validity_days: int = 30,
) -> SourceRegistryManifest:
    private_bytes = base64.b64decode(
        private_key_b64,
        validate=True,
    )

    if len(private_bytes) != ED25519_PRIVATE_KEY_BYTES:
        raise ValueError("Registry Ed25519 private key must decode to exactly 32 bytes.")

    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

    issued = issued_at or datetime.now(UTC)

    expiry = expires_at or (issued + timedelta(days=validity_days))

    placeholder = base64.b64encode(b"\x00" * 64).decode("ascii")

    manifest = SourceRegistryManifest(
        registry_sha256=(source_registry_sha256(registry)),
        generation=generation,
        issued_at=issued,
        expires_at=expiry,
        signer_id=signer_id,
        algorithm="ed25519",
        signature_b64=placeholder,
    )

    signature = private_key.sign(registry_manifest_signing_bytes(manifest))

    return manifest.model_copy(
        update={"signature_b64": (base64.b64encode(signature).decode("ascii"))}
    )


def load_source_registry_manifest(
    path: Path | str,
) -> SourceRegistryManifest:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))

        return SourceRegistryManifest.model_validate(data)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise SourceRegistryVerificationError(
            "Source-registry manifest is unreadable or invalid."
        ) from exc


def verify_source_registry_manifest(
    *,
    registry: IntelligenceSourceRegistry,
    manifest: SourceRegistryManifest,
    trust_store: TrustStore,
    now: datetime | None = None,
) -> SourceRegistryTrustDecision:
    digest = source_registry_sha256(registry)

    base = {
        "registry_id": manifest.registry_id,
        "registry_sha256": digest,
        "signer_id": manifest.signer_id,
        "algorithm": manifest.algorithm,
    }

    if manifest.algorithm != "ed25519":
        return SourceRegistryTrustDecision(
            state=(SourceRegistryTrustState.UNSUPPORTED_ALGORITHM),
            trusted=False,
            **base,
            rationale=["Registry manifest signature algorithm is unsupported."],
        )

    if manifest.registry_sha256 != digest:
        return SourceRegistryTrustDecision(
            state=(SourceRegistryTrustState.DIGEST_MISMATCH),
            trusted=False,
            **base,
            rationale=["Registry manifest SHA-256 does not match registry content."],
        )

    signer = next(
        (
            item
            for item in trust_store.signers
            if (item.signer_id == manifest.signer_id and item.enabled)
        ),
        None,
    )

    if signer is None:
        return SourceRegistryTrustDecision(
            state=(SourceRegistryTrustState.UNKNOWN_SIGNER),
            trusted=False,
            **base,
            rationale=[
                (
                    "Registry signer is not present as an enabled signer "
                    "in the dedicated registry trust store."
                )
            ],
        )

    if signer.algorithm != manifest.algorithm or signer.algorithm != "ed25519":
        return SourceRegistryTrustDecision(
            state=(SourceRegistryTrustState.UNSUPPORTED_ALGORITHM),
            trusted=False,
            **base,
            rationale=["Registry signer algorithm does not match Ed25519."],
        )

    try:
        public_key_bytes = base64.b64decode(
            signer.public_key_b64,
            validate=True,
        )

        signature = base64.b64decode(
            manifest.signature_b64,
            validate=True,
        )

        if len(public_key_bytes) != ED25519_PUBLIC_KEY_BYTES:
            raise ValueError("Invalid registry Ed25519 public-key length.")

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        public_key.verify(
            signature,
            registry_manifest_signing_bytes(manifest),
        )

    except (
        ValueError,
        InvalidSignature,
    ):
        return SourceRegistryTrustDecision(
            state=(SourceRegistryTrustState.INVALID_SIGNATURE),
            trusted=False,
            **base,
            rationale=["Registry Ed25519 signature verification failed."],
        )

    delegation_evidence = resolve_authorized_predecessor_evidence(
        trust_store=trust_store,
        successor_signer_id=(manifest.signer_id),
        successor_public_key_b64=(signer.public_key_b64),
        context="registry",
        now=now,
    )

    authorized_predecessors = sorted(delegation_evidence)

    predecessor_minimum_generations = {
        predecessor_id: (evidence.minimum_successor_generation)
        for predecessor_id, evidence in delegation_evidence.items()
    }

    rationale = [
        "Registry digest matches the signed manifest.",
        ("Registry Ed25519 signature verified against the dedicated local registry trust store."),
        ("Registry signature uses the PHP Sentinel source-registry domain separator."),
    ]

    if signer.authorized_predecessors:
        rationale.append(
            "Legacy authorized_predecessors metadata is present "
            "but is not accepted as registry rotation authority."
        )

    if authorized_predecessors:
        rationale.append(
            "Registry signer rotation authorization was "
            "established by valid predecessor-signed delegation."
        )

    return SourceRegistryTrustDecision(
        state=SourceRegistryTrustState.TRUSTED,
        trusted=True,
        **base,
        authorized_predecessor_signer_ids=(authorized_predecessors),
        authorized_predecessor_minimum_generations=(predecessor_minimum_generations),
        authorized_predecessor_delegations=(delegation_evidence),
        rationale=rationale,
    )


def evaluate_source_registry_lifecycle(
    *,
    registry: IntelligenceSourceRegistry,
    manifest: SourceRegistryManifest,
    trust: SourceRegistryTrustDecision,
    state: SourceRegistryStateStore | None = None,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> SourceRegistryLifecycleDecision:
    current_time = now or datetime.now(UTC)

    digest = source_registry_sha256(registry)

    base = {
        "registry_id": manifest.registry_id,
        "registry_sha256": digest,
        "generation": manifest.generation,
        "issued_at": manifest.issued_at,
        "expires_at": manifest.expires_at,
        "signer_id": trust.signer_id,
        "minimum_generation": minimum_generation,
        "maximum_age_days": maximum_age_days,
    }

    future_limit = current_time + timedelta(seconds=maximum_future_skew_seconds)

    if manifest.issued_at > future_limit:
        return SourceRegistryLifecycleDecision(
            state=(SourceRegistryLifecycleState.FUTURE_ISSUED),
            activatable=False,
            **base,
            rationale=["Registry manifest issued_at is too far in the future."],
        )

    if current_time >= manifest.expires_at:
        return SourceRegistryLifecycleDecision(
            state=(SourceRegistryLifecycleState.EXPIRED),
            activatable=False,
            **base,
            rationale=["Registry manifest has expired."],
        )

    if current_time - manifest.issued_at > timedelta(days=maximum_age_days):
        return SourceRegistryLifecycleDecision(
            state=(SourceRegistryLifecycleState.STALE),
            activatable=False,
            **base,
            rationale=["Registry manifest exceeds the maximum accepted age."],
        )

    if manifest.generation < minimum_generation:
        return SourceRegistryLifecycleDecision(
            state=(SourceRegistryLifecycleState.BELOW_MINIMUM_GENERATION),
            activatable=False,
            **base,
            rationale=["Registry generation is below the operator minimum."],
        )

    record = None

    if state is not None:
        record = state.records.get(manifest.registry_id)

    if record is not None:
        if trust.signer_id != record.signer_id:
            delegated_minimum = trust.authorized_predecessor_minimum_generations.get(
                record.signer_id
            )

            delegation_evidence = trust.authorized_predecessor_delegations.get(record.signer_id)

            delegation_key = f"registry|{record.signer_id}|{trust.signer_id}"

            historical_delegation = (
                state.delegation_records.get(delegation_key) if state is not None else None
            )

            delegation_history_valid = delegation_evidence is not None

            if delegation_evidence is not None and state is not None:
                revocation_key = (
                    f"registry|{record.signer_id}|{trust.signer_id}|"
                    f"{delegation_evidence.sequence}|"
                    f"{delegation_evidence.delegation_sha256}"
                )

                if revocation_key in state.revocation_records:
                    delegation_history_valid = False

            if delegation_evidence is not None and historical_delegation is not None:
                if delegation_evidence.sequence < historical_delegation.sequence:
                    delegation_history_valid = False

                if delegation_evidence.sequence == historical_delegation.sequence and (
                    delegation_evidence.delegation_sha256 != historical_delegation.delegation_sha256
                ):
                    delegation_history_valid = False

            rotation_authorized = (
                record.signer_id in trust.authorized_predecessor_signer_ids
                and delegated_minimum is not None
                and delegation_history_valid
                and manifest.generation >= delegated_minimum
                and manifest.generation > record.generation
            )

            if not rotation_authorized:
                return SourceRegistryLifecycleDecision(
                    state=(SourceRegistryLifecycleState.SIGNER_CHANGED),
                    activatable=False,
                    **base,
                    rationale=[
                        (
                            "Registry signer differs from the signer "
                            "pinned by the previously accepted generation."
                        )
                    ],
                )

        if manifest.generation < record.generation:
            return SourceRegistryLifecycleDecision(
                state=(SourceRegistryLifecycleState.ROLLBACK_DETECTED),
                activatable=False,
                **base,
                rationale=[
                    (
                        "Registry generation is lower than the highest "
                        "previously accepted generation."
                    )
                ],
            )

        if manifest.generation == record.generation and digest != record.registry_sha256:
            return SourceRegistryLifecycleDecision(
                state=(SourceRegistryLifecycleState.REPLAY_DETECTED),
                activatable=False,
                **base,
                rationale=[
                    ("Different registry content was presented for an already accepted generation.")
                ],
            )

    rotation_predecessor = None
    rotation_sequence = None
    rotation_digest = None

    if record is not None and trust.signer_id != record.signer_id:
        selected = trust.authorized_predecessor_delegations.get(record.signer_id)

        if selected is not None:
            rotation_predecessor = record.signer_id
            rotation_sequence = selected.sequence
            rotation_digest = selected.delegation_sha256

    return SourceRegistryLifecycleDecision(
        state=SourceRegistryLifecycleState.CURRENT,
        activatable=trust.trusted,
        **base,
        rotation_predecessor_signer_id=(rotation_predecessor),
        rotation_delegation_sequence=(rotation_sequence),
        rotation_delegation_sha256=(rotation_digest),
        rationale=[
            (
                "Registry signature, freshness, expiry, generation, "
                "signer pin, and rollback checks passed."
            )
        ],
    )


def load_source_registry_state(
    path: Path | str,
) -> SourceRegistryStateStore:
    state_path = Path(path)

    if not state_path.exists():
        return SourceRegistryStateStore()

    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))

        return SourceRegistryStateStore.model_validate(data)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise SourceRegistryStateStorageError(
            "Source-registry state is unreadable, malformed, or unsupported."
        ) from exc


def _secure_registry_directory(
    directory: Path,
) -> None:
    directory.mkdir(
        parents=True,
        exist_ok=True,
        mode=REGISTRY_STATE_DIRECTORY_MODE,
    )

    try:
        directory.chmod(REGISTRY_STATE_DIRECTORY_MODE)
    except OSError:
        pass


def _secure_registry_file(
    path: Path,
) -> None:
    try:
        path.chmod(REGISTRY_STATE_FILE_MODE)
    except OSError:
        pass


def _directory_fsync(
    directory: Path,
) -> None:
    flags = os.O_RDONLY

    if hasattr(
        os,
        "O_DIRECTORY",
    ):
        flags |= os.O_DIRECTORY

    try:
        descriptor = os.open(
            directory,
            flags,
        )
    except OSError:
        return

    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _save_source_registry_state_unlocked(
    path: Path | str,
    state: SourceRegistryStateStore,
) -> None:
    state_path = Path(path)

    _secure_registry_directory(state_path.parent)

    temporary = state_path.with_suffix(state_path.suffix + ".tmp")

    payload = (
        json.dumps(
            state.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    descriptor: int | None = None

    try:
        descriptor = os.open(
            temporary,
            (os.O_WRONLY | os.O_CREAT | os.O_TRUNC),
            REGISTRY_STATE_FILE_MODE,
        )

        with os.fdopen(
            descriptor,
            "wb",
            closefd=True,
        ) as handle:
            descriptor = None

            handle.write(payload)

            handle.flush()

            os.fsync(handle.fileno())

        _secure_registry_file(temporary)

        os.replace(
            temporary,
            state_path,
        )

        _secure_registry_file(state_path)

        _directory_fsync(state_path.parent)

    except OSError as exc:
        raise SourceRegistryStateStorageError(
            "Failed to durably persist source-registry lifecycle state."
        ) from exc

    finally:
        if descriptor is not None:
            os.close(descriptor)

        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def save_source_registry_state(
    path: Path | str,
    state: SourceRegistryStateStore,
) -> None:
    with lifecycle_state_lock(path):
        _save_source_registry_state_unlocked(
            path,
            state,
        )


def record_observed_source_registry_revocations(
    *,
    path: Path | str,
    revocations,
    expected_state: SourceRegistryStateStore,
    now: datetime | None = None,
) -> SourceRegistryStateStore:
    observed_at = now or datetime.now(UTC)

    with lifecycle_state_lock(path):
        current = load_source_registry_state(path)

        if current.model_dump(mode="json") != expected_state.model_dump(mode="json"):
            raise SourceRegistryStateStorageError(
                "Source-registry lifecycle state changed before revocation observation commit."
            )

        updated = current.model_copy(deep=True)

        for revocation in revocations:
            key = (
                f"{revocation.context}|"
                f"{revocation.predecessor_signer_id}|"
                f"{revocation.successor_signer_id}|"
                f"{revocation.delegation_sequence}|"
                f"{revocation.delegation_sha256}"
            )

            digest = signer_delegation_revocation_sha256(revocation)
            historical = updated.revocation_records.get(key)

            if historical is not None:
                if revocation.revocation_sequence < historical.revocation_sequence:
                    raise SourceRegistryStateStorageError(
                        "Refusing to persist an older registry delegation revocation sequence."
                    )

                if (
                    revocation.revocation_sequence == historical.revocation_sequence
                    and digest != historical.revocation_sha256
                ):
                    raise SourceRegistryStateStorageError(
                        "Refusing same-sequence registry delegation revocation digest replacement."
                    )

            updated.revocation_records[key] = DelegationRevocationHistoryRecord(
                delegation_sequence=revocation.delegation_sequence,
                delegation_sha256=revocation.delegation_sha256,
                revocation_sequence=revocation.revocation_sequence,
                revocation_sha256=digest,
                observed_at=observed_at,
            )

        _save_source_registry_state_unlocked(
            path,
            updated,
        )

        return updated


def record_accepted_source_registry(
    *,
    path: Path | str,
    registry: IntelligenceSourceRegistry,
    manifest: SourceRegistryManifest,
    lifecycle: SourceRegistryLifecycleDecision,
    expected_state: SourceRegistryStateStore,
    now: datetime | None = None,
) -> SourceRegistryStateStore:
    if not lifecycle.activatable:
        raise SourceRegistryStateStorageError("Cannot record a non-activatable source registry.")

    accepted_at = now or datetime.now(UTC)

    with lifecycle_state_lock(path):
        current = load_source_registry_state(path)

        if current.model_dump(mode="json") != expected_state.model_dump(mode="json"):
            raise SourceRegistryStateStorageError(
                "Source-registry lifecycle state changed between evaluation and commit."
            )

        existing = current.records.get(manifest.registry_id)

        digest = source_registry_sha256(registry)

        if existing is not None:
            if manifest.generation < existing.generation:
                raise SourceRegistryStateStorageError(
                    "Refusing to persist a lower registry generation."
                )

            if manifest.generation == existing.generation and digest != existing.registry_sha256:
                raise SourceRegistryStateStorageError(
                    "Refusing same-generation registry digest replacement."
                )

        updated = current.model_copy(deep=True)

        if (
            lifecycle.rotation_predecessor_signer_id is not None
            and lifecycle.rotation_delegation_sequence is not None
            and lifecycle.rotation_delegation_sha256 is not None
        ):
            delegation_key = (
                f"registry|{lifecycle.rotation_predecessor_signer_id}|{lifecycle.signer_id}"
            )

            historical = updated.delegation_records.get(delegation_key)

            if historical is not None:
                if lifecycle.rotation_delegation_sequence < historical.sequence:
                    raise SourceRegistryStateStorageError(
                        "Refusing to persist an older registry delegation sequence."
                    )

                if lifecycle.rotation_delegation_sequence == historical.sequence and (
                    lifecycle.rotation_delegation_sha256 != historical.delegation_sha256
                ):
                    raise SourceRegistryStateStorageError(
                        "Refusing same-sequence registry delegation digest replacement."
                    )

            updated.delegation_records[delegation_key] = DelegationHistoryRecord(
                sequence=(lifecycle.rotation_delegation_sequence),
                delegation_sha256=(lifecycle.rotation_delegation_sha256),
                accepted_at=accepted_at,
            )

        updated.records[manifest.registry_id] = SourceRegistryStateRecord(
            generation=manifest.generation,
            registry_sha256=digest,
            signer_id=(lifecycle.signer_id or manifest.signer_id),
            accepted_at=accepted_at,
        )

        _save_source_registry_state_unlocked(
            path,
            updated,
        )

        return updated


def verify_signed_source_registry(
    *,
    registry_path: Path | str,
    manifest_path: Path | str,
    registry_trust_store_path: Path | str,
    registry_state_path: Path | str,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> VerifiedSourceRegistry:
    from php_sentinel.intelligence.source_registry import (
        load_source_registry,
    )

    registry = load_source_registry(registry_path)

    manifest = load_source_registry_manifest(manifest_path)

    trust_store = load_trust_store(registry_trust_store_path)

    trust = verify_source_registry_manifest(
        registry=registry,
        manifest=manifest,
        trust_store=trust_store,
        now=now,
    )

    if not trust.trusted:
        raise SourceRegistryVerificationError(
            f"Source-registry trust verification failed: {trust.state.value}."
        )

    state = load_source_registry_state(registry_state_path)

    lifecycle = evaluate_source_registry_lifecycle(
        registry=registry,
        manifest=manifest,
        trust=trust,
        state=state,
        minimum_generation=minimum_generation,
        maximum_age_days=maximum_age_days,
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )

    if not lifecycle.activatable:
        raise SourceRegistryVerificationError(
            f"Source-registry lifecycle verification failed: {lifecycle.state.value}."
        )

    return VerifiedSourceRegistry(
        registry=registry,
        manifest=manifest,
        trust=trust,
        lifecycle=lifecycle,
        state_snapshot=state,
        _capability=_REGISTRY_CAPABILITY,
    )


def activate_signed_source_registry(
    *,
    registry_path: Path | str,
    manifest_path: Path | str,
    registry_trust_store_path: Path | str,
    registry_state_path: Path | str,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> VerifiedSourceRegistry:
    from php_sentinel.intelligence.source_registry import (
        load_source_registry,
    )

    registry = load_source_registry(registry_path)
    manifest = load_source_registry_manifest(manifest_path)
    trust_store = load_trust_store(registry_trust_store_path)

    trust = verify_source_registry_manifest(
        registry=registry,
        manifest=manifest,
        trust_store=trust_store,
        now=now,
    )

    if not trust.trusted:
        raise SourceRegistryVerificationError(
            f"Source-registry trust verification failed: {trust.state.value}."
        )

    state = load_source_registry_state(registry_state_path)

    revocations = resolve_verified_delegation_revocations(
        trust_store=trust_store,
        successor_signer_id=manifest.signer_id,
        context="registry",
        now=now,
    )

    if revocations:
        state = record_observed_source_registry_revocations(
            path=registry_state_path,
            revocations=revocations,
            expected_state=state,
            now=now,
        )

    lifecycle = evaluate_source_registry_lifecycle(
        registry=registry,
        manifest=manifest,
        trust=trust,
        state=state,
        minimum_generation=minimum_generation,
        maximum_age_days=maximum_age_days,
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )

    if not lifecycle.activatable:
        raise SourceRegistryVerificationError(
            f"Source-registry lifecycle verification failed: {lifecycle.state.value}."
        )

    verified = VerifiedSourceRegistry(
        registry=registry,
        manifest=manifest,
        trust=trust,
        lifecycle=lifecycle,
        state_snapshot=state,
        _capability=_REGISTRY_CAPABILITY,
    )

    record_accepted_source_registry(
        path=registry_state_path,
        registry=registry,
        manifest=manifest,
        lifecycle=lifecycle,
        expected_state=state,
        now=now,
    )

    return verified


def stage_bundle_with_signed_registry(
    *,
    registry_path: Path | str,
    registry_manifest_path: Path | str,
    registry_trust_store_path: Path | str,
    registry_state_path: Path | str,
    source_id: str,
    channel: str,
    staging_directory: Path | str,
    timeout_seconds: float = 15.0,
    maximum_bytes: int = 2 * 1024 * 1024,
    client=None,
    resolver=None,
    peer_address_getter=None,
    registry_minimum_generation: int = 1,
    registry_maximum_age_days: int = 30,
    registry_maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
):
    """
    Stage intelligence only after authenticating the source registry.

    Registry verification is read-only here: staging remote bytes does not
    advance registry lifecycle state.
    """

    verified_registry = verify_signed_source_registry(
        registry_path=registry_path,
        manifest_path=registry_manifest_path,
        registry_trust_store_path=(registry_trust_store_path),
        registry_state_path=registry_state_path,
        minimum_generation=(registry_minimum_generation),
        maximum_age_days=(registry_maximum_age_days),
        maximum_future_skew_seconds=(registry_maximum_future_skew_seconds),
        now=now,
    )

    metadata = stage_registry_bundle_from_registry(
        registry=verified_registry.registry,
        source_id=source_id,
        channel=channel,
        staging_directory=staging_directory,
        timeout_seconds=timeout_seconds,
        maximum_bytes=maximum_bytes,
        client=client,
        resolver=resolver,
        peer_address_getter=(peer_address_getter),
        now=now,
    )

    return (
        verified_registry,
        metadata,
    )


def verify_staged_bundle_with_signed_registry(
    *,
    registry_path: Path | str,
    registry_manifest_path: Path | str,
    registry_trust_store_path: Path | str,
    registry_state_path: Path | str,
    source_id: str,
    channel: str,
    staging_directory: Path | str,
    intelligence_trust_store_path: Path | str,
    intelligence_lifecycle_state_path: Path | str,
    registry_minimum_generation: int = 1,
    registry_maximum_age_days: int = 30,
    registry_maximum_future_skew_seconds: int = 300,
    intelligence_minimum_generation: int = 1,
    intelligence_maximum_age_days: int = 30,
    intelligence_maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
):
    """
    Verify staged intelligence against authenticated source policy.

    Registry trust and intelligence trust remain independent. Verification
    does not commit either lifecycle state.
    """

    verified_registry = verify_signed_source_registry(
        registry_path=registry_path,
        manifest_path=registry_manifest_path,
        registry_trust_store_path=(registry_trust_store_path),
        registry_state_path=registry_state_path,
        minimum_generation=(registry_minimum_generation),
        maximum_age_days=(registry_maximum_age_days),
        maximum_future_skew_seconds=(registry_maximum_future_skew_seconds),
        now=now,
    )

    candidate = verify_registry_staged_bundle_from_registry(
        registry=verified_registry.registry,
        source_id=source_id,
        channel=channel,
        staging_directory=staging_directory,
        trust_store_path=(intelligence_trust_store_path),
        lifecycle_state_path=(intelligence_lifecycle_state_path),
        minimum_generation=(intelligence_minimum_generation),
        maximum_age_days=(intelligence_maximum_age_days),
        maximum_future_skew_seconds=(intelligence_maximum_future_skew_seconds),
        now=now,
    )

    return (
        verified_registry,
        candidate,
    )


def activate_cached_intelligence_with_signed_registry(
    *,
    registry_path: Path | str,
    registry_manifest_path: Path | str,
    registry_trust_store_path: Path | str,
    registry_state_path: Path | str,
    source_id: str,
    channel: str,
    verified_root: Path | str,
    intelligence_trust_store_path: Path | str,
    intelligence_lifecycle_state_path: Path | str,
    policy_id: str | None = None,
    registry_minimum_generation: int = 1,
    registry_maximum_age_days: int = 30,
    intelligence_minimum_generation: int = 1,
    intelligence_maximum_age_days: int = 30,
    now: datetime | None = None,
):
    """
    Activate intelligence using an authenticated registry.

    Registry trust and intelligence trust remain independent authorities.
    """

    verified_registry = activate_signed_source_registry(
        registry_path=registry_path,
        manifest_path=registry_manifest_path,
        registry_trust_store_path=(registry_trust_store_path),
        registry_state_path=(registry_state_path),
        minimum_generation=(registry_minimum_generation),
        maximum_age_days=(registry_maximum_age_days),
        now=now,
    )

    entry, activated = activate_registry_cached_intelligence_from_registry(
        registry=verified_registry.registry,
        source_id=source_id,
        channel=channel,
        verified_root=verified_root,
        trust_store_path=(intelligence_trust_store_path),
        lifecycle_state_path=(intelligence_lifecycle_state_path),
        policy_id=policy_id,
        minimum_generation=(intelligence_minimum_generation),
        maximum_age_days=(intelligence_maximum_age_days),
        now=now,
    )

    return (
        verified_registry,
        entry,
        activated,
    )
