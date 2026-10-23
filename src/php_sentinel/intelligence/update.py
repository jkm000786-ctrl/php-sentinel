from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from php_sentinel.intelligence.activation import (
    VerifiedIntelligenceSelection,
    activate_verified_intelligence,
)
from php_sentinel.intelligence.lifecycle import (
    evaluate_lifecycle,
    load_lifecycle_state,
)
from php_sentinel.intelligence.repository import (
    load_policy,
    policy_sha256,
)
from php_sentinel.intelligence.trust import (
    load_manifest,
    load_trust_store,
    verify_manifest,
)
from php_sentinel.models.intelligence_lifecycle import (
    IntelligenceLifecycleDecision,
    IntelligenceLifecyclePolicy,
    LifecycleStateStore,
)
from php_sentinel.models.intelligence_policy import (
    IntelligencePolicy,
)
from php_sentinel.models.intelligence_trust import (
    IntelligenceManifest,
    IntelligenceTrustDecision,
)
from php_sentinel.models.intelligence_update import (
    IntelligenceUpdateStageMetadata,
    IntelligenceUpdateVerificationMetadata,
    IntelligenceVerifiedCacheEntry,
)

DEFAULT_UPDATE_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_UPDATE_TIMEOUT_SECONDS = 15.0

STAGED_POLICY_FILENAME = "policy.json"
STAGED_MANIFEST_FILENAME = "manifest.json"
STAGE_METADATA_FILENAME = "stage-metadata.json"

VERIFIED_POLICY_FILENAME = "policy.json"
VERIFIED_MANIFEST_FILENAME = "manifest.json"
VERIFICATION_METADATA_FILENAME = "verification.json"


class IntelligenceUpdateError(ValueError):
    """Base error for the intelligence update channel."""


class IntelligenceUpdateTransportError(IntelligenceUpdateError):
    """Raised when remote staging fails."""


class IntelligenceUpdateVerificationError(IntelligenceUpdateError):
    """Raised when staged intelligence fails verification."""


class IntelligenceUpdatePromotionError(IntelligenceUpdateError):
    """Raised when verified intelligence cannot be promoted."""


class IntelligenceVerifiedCacheError(IntelligenceUpdateError):
    """Raised when verified-cache inspection fails closed."""


_UPDATE_CAPABILITY = object()


class VerifiedUpdateCandidate:
    """
    In-process capability proving the staged bundle passed the local
    trust and lifecycle verification path.

    This is an architectural boundary, not protection against a hostile
    process capable of monkey-patching PHP Sentinel itself.
    """

    __slots__ = (
        "lifecycle",
        "manifest",
        "policy",
        "stage_directory",
        "stage_metadata",
        "state_snapshot",
        "trust",
        "verification_metadata",
    )

    def __init__(
        self,
        *,
        policy: IntelligencePolicy,
        manifest: IntelligenceManifest,
        trust: IntelligenceTrustDecision,
        lifecycle: IntelligenceLifecycleDecision,
        state_snapshot: LifecycleStateStore,
        stage_directory: Path,
        stage_metadata: IntelligenceUpdateStageMetadata,
        verification_metadata: IntelligenceUpdateVerificationMetadata,
        _capability: object | None = None,
    ) -> None:
        if _capability is not _UPDATE_CAPABILITY:
            raise TypeError("VerifiedUpdateCandidate cannot be constructed directly.")

        if not trust.trusted:
            raise ValueError("Verified update candidate requires trusted intelligence.")

        if not lifecycle.activatable:
            raise ValueError("Verified update candidate requires an activatable lifecycle.")

        self.policy = policy
        self.manifest = manifest
        self.trust = trust
        self.lifecycle = lifecycle
        self.state_snapshot = state_snapshot
        self.stage_directory = stage_directory
        self.stage_metadata = stage_metadata
        self.verification_metadata = verification_metadata


def _sha256_bytes(
    payload: bytes,
) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_remote_url(
    value: str,
) -> None:
    parsed = urlsplit(value)

    if parsed.scheme.lower() != "https":
        raise IntelligenceUpdateTransportError("Intelligence update URLs must use HTTPS.")

    if not parsed.hostname:
        raise IntelligenceUpdateTransportError("Intelligence update URL must include a hostname.")

    if parsed.username is not None or parsed.password is not None:
        raise IntelligenceUpdateTransportError(
            "Credentials embedded in intelligence update URLs are not allowed."
        )

    if parsed.fragment:
        raise IntelligenceUpdateTransportError(
            "Intelligence update URLs must not contain fragments."
        )


def _fetch_bytes(
    *,
    client: httpx.Client,
    url: str,
    maximum_bytes: int,
) -> bytes:
    try:
        with client.stream(
            "GET",
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": ("PHP-Sentinel-Intelligence-Updater/0.1"),
            },
        ) as response:
            if response.is_redirect:
                raise IntelligenceUpdateTransportError(
                    "Intelligence update redirects are not followed."
                )

            response.raise_for_status()

            chunks: list[bytes] = []
            total = 0

            for chunk in response.iter_bytes():
                total += len(chunk)

                if total > maximum_bytes:
                    raise IntelligenceUpdateTransportError(
                        "Intelligence update object exceeds the configured maximum download size."
                    )

                chunks.append(chunk)

    except IntelligenceUpdateTransportError:
        raise

    except httpx.HTTPError as exc:
        raise IntelligenceUpdateTransportError(
            f"Intelligence update transport failed for {url}: {exc}"
        ) from exc

    payload = b"".join(chunks)

    if not payload:
        raise IntelligenceUpdateTransportError("Intelligence update object was empty.")

    return payload


def _atomic_write_bytes(
    path: Path,
    payload: bytes,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )

    temporary = Path(temporary_name)

    try:
        with os.fdopen(
            descriptor,
            "wb",
            closefd=True,
        ) as handle:
            handle.write(payload)

            handle.flush()

            os.fsync(handle.fileno())

        os.replace(
            temporary,
            path,
        )

    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_json(
    path: Path,
    payload: dict[str, object],
) -> None:
    _atomic_write_bytes(
        path,
        (
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8"),
    )


def stage_remote_bundle(
    *,
    policy_url: str,
    manifest_url: str,
    staging_directory: Path | str,
    timeout_seconds: float = DEFAULT_UPDATE_TIMEOUT_SECONDS,
    maximum_bytes: int = DEFAULT_UPDATE_MAX_BYTES,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> IntelligenceUpdateStageMetadata:
    """
    Download policy and manifest into untrusted staging.

    Transport success establishes no intelligence trust.
    """

    _validate_remote_url(policy_url)

    _validate_remote_url(manifest_url)

    stage = Path(staging_directory)

    selected_client = client
    owns_client = False

    if selected_client is None:
        selected_client = httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
        )

        owns_client = True

    try:
        policy_bytes = _fetch_bytes(
            client=selected_client,
            url=policy_url,
            maximum_bytes=maximum_bytes,
        )

        manifest_bytes = _fetch_bytes(
            client=selected_client,
            url=manifest_url,
            maximum_bytes=maximum_bytes,
        )

    finally:
        if owns_client:
            selected_client.close()

    metadata = IntelligenceUpdateStageMetadata(
        policy_url=policy_url,
        manifest_url=manifest_url,
        fetched_at=(now or datetime.now(UTC)),
        policy_transport_sha256=(_sha256_bytes(policy_bytes)),
        manifest_transport_sha256=(_sha256_bytes(manifest_bytes)),
        policy_bytes=len(policy_bytes),
        manifest_bytes=len(manifest_bytes),
    )

    stage.mkdir(
        parents=True,
        exist_ok=True,
    )

    _atomic_write_bytes(
        stage / STAGED_POLICY_FILENAME,
        policy_bytes,
    )

    _atomic_write_bytes(
        stage / STAGED_MANIFEST_FILENAME,
        manifest_bytes,
    )

    _write_json(
        stage / STAGE_METADATA_FILENAME,
        metadata.model_dump(mode="json"),
    )

    return metadata


def load_stage_metadata(
    staging_directory: Path | str,
) -> IntelligenceUpdateStageMetadata:
    path = Path(staging_directory) / STAGE_METADATA_FILENAME

    try:
        data = json.loads(path.read_text(encoding="utf-8"))

        metadata = IntelligenceUpdateStageMetadata.model_validate(data)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise IntelligenceUpdateVerificationError(
            "Staged intelligence metadata is missing or invalid."
        ) from exc

    if metadata.metadata_version != 1:
        raise IntelligenceUpdateVerificationError(
            "Unsupported intelligence update stage metadata version."
        )

    return metadata


def _validate_staged_transport_integrity(
    staging_directory: Path,
    metadata: IntelligenceUpdateStageMetadata,
) -> tuple[
    bytes,
    bytes,
]:
    try:
        policy_bytes = staging_directory.joinpath(STAGED_POLICY_FILENAME).read_bytes()

        manifest_bytes = staging_directory.joinpath(STAGED_MANIFEST_FILENAME).read_bytes()

    except OSError as exc:
        raise IntelligenceUpdateVerificationError(
            "Staged intelligence bundle is incomplete."
        ) from exc

    if _sha256_bytes(policy_bytes) != metadata.policy_transport_sha256:
        raise IntelligenceUpdateVerificationError(
            "Staged policy transport digest changed after download."
        )

    if _sha256_bytes(manifest_bytes) != metadata.manifest_transport_sha256:
        raise IntelligenceUpdateVerificationError(
            "Staged manifest transport digest changed after download."
        )

    return (
        policy_bytes,
        manifest_bytes,
    )


def verify_staged_bundle(
    *,
    staging_directory: Path | str,
    trust_store_path: Path | str,
    lifecycle_state_path: Path | str,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> VerifiedUpdateCandidate:
    """
    Verify staged content against the operator's LOCAL trust store and
    lifecycle rollback state.

    This does not mutate lifecycle state and does not activate the policy.
    """

    stage = Path(staging_directory)

    metadata = load_stage_metadata(stage)

    _validate_staged_transport_integrity(
        stage,
        metadata,
    )

    try:
        policy = load_policy(stage / STAGED_POLICY_FILENAME)

        manifest = load_manifest(stage / STAGED_MANIFEST_FILENAME)

        trust_store = load_trust_store(trust_store_path)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise IntelligenceUpdateVerificationError(
            f"Staged intelligence parsing failed: {exc}"
        ) from exc

    trust = verify_manifest(
        policy,
        manifest,
        trust_store,
    )

    if not trust.trusted:
        raise IntelligenceUpdateVerificationError(
            f"Staged intelligence trust verification failed: {trust.state.value}."
        )

    state = load_lifecycle_state(lifecycle_state_path)

    lifecycle = evaluate_lifecycle(
        policy=policy,
        manifest=manifest,
        trust=trust,
        lifecycle_policy=(
            IntelligenceLifecyclePolicy(
                minimum_generation=(minimum_generation),
                maximum_age_days=(maximum_age_days),
                maximum_future_skew_seconds=(maximum_future_skew_seconds),
            )
        ),
        state=state,
        now=now,
    )

    if not lifecycle.activatable:
        raise IntelligenceUpdateVerificationError(
            f"Staged intelligence lifecycle verification failed: {lifecycle.state.value}."
        )

    if manifest.generation is None:
        raise IntelligenceUpdateVerificationError(
            "Verified staged manifest lacks a lifecycle generation."
        )

    verification = IntelligenceUpdateVerificationMetadata(
        policy_id=(policy.policy_id),
        policy_sha256=(policy_sha256(policy)),
        manifest_version=(manifest.manifest_version),
        generation=(manifest.generation),
        signer_id=(manifest.signer_id),
        trust_state=(trust.state.value),
        lifecycle_state=(lifecycle.state.value),
        trusted=(trust.trusted),
        activatable=(lifecycle.activatable),
        verified_at=(now or datetime.now(UTC)),
        source_policy_url=(metadata.policy_url),
        source_manifest_url=(metadata.manifest_url),
        staged_policy_transport_sha256=(metadata.policy_transport_sha256),
        staged_manifest_transport_sha256=(metadata.manifest_transport_sha256),
    )

    return VerifiedUpdateCandidate(
        policy=policy,
        manifest=manifest,
        trust=trust,
        lifecycle=lifecycle,
        state_snapshot=state,
        stage_directory=stage,
        stage_metadata=metadata,
        verification_metadata=(verification),
        _capability=(_UPDATE_CAPABILITY),
    )


def _candidate_cache_name(
    candidate: VerifiedUpdateCandidate,
) -> str:
    generation = candidate.manifest.generation

    return (
        f"{candidate.policy.policy_id}"
        f"-g{generation}"
        f"-{candidate.verification_metadata.policy_sha256[:12]}"
    )


def promote_verified_candidate(
    *,
    candidate: VerifiedUpdateCandidate,
    verified_root: Path | str,
) -> Path:
    """
    Promote a verified staged bundle into an immutable verified cache.

    Promotion is NOT activation and does not update lifecycle acceptance
    state. Existing activation code must still re-verify the cached bundle.
    """

    stage = candidate.stage_directory

    metadata = load_stage_metadata(stage)

    policy_bytes, manifest_bytes = _validate_staged_transport_integrity(
        stage,
        metadata,
    )

    if metadata != candidate.stage_metadata:
        raise IntelligenceUpdatePromotionError("Staged update metadata changed after verification.")

    try:
        reparsed_policy = load_policy(stage / STAGED_POLICY_FILENAME)

        reparsed_manifest = load_manifest(stage / STAGED_MANIFEST_FILENAME)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise IntelligenceUpdatePromotionError(
            "Staged intelligence changed after verification."
        ) from exc

    if policy_sha256(reparsed_policy) != candidate.verification_metadata.policy_sha256:
        raise IntelligenceUpdatePromotionError("Staged policy changed after verification.")

    if reparsed_manifest.model_dump(mode="json") != candidate.manifest.model_dump(mode="json"):
        raise IntelligenceUpdatePromotionError("Staged manifest changed after verification.")

    root = Path(verified_root)

    root.mkdir(
        parents=True,
        exist_ok=True,
    )

    final_directory = root / _candidate_cache_name(candidate)

    if final_directory.exists():
        existing_policy = final_directory / VERIFIED_POLICY_FILENAME

        existing_manifest = final_directory / VERIFIED_MANIFEST_FILENAME

        if (
            existing_policy.exists()
            and existing_manifest.exists()
            and existing_policy.read_bytes() == policy_bytes
            and existing_manifest.read_bytes() == manifest_bytes
        ):
            return final_directory

        raise IntelligenceUpdatePromotionError(
            "Verified cache destination already exists with different content."
        )

    temporary = Path(
        tempfile.mkdtemp(
            prefix=".verified-update-",
            dir=root,
        )
    )

    try:
        _atomic_write_bytes(
            temporary / VERIFIED_POLICY_FILENAME,
            policy_bytes,
        )

        _atomic_write_bytes(
            temporary / VERIFIED_MANIFEST_FILENAME,
            manifest_bytes,
        )

        _write_json(
            temporary / VERIFICATION_METADATA_FILENAME,
            candidate.verification_metadata.model_dump(mode="json"),
        )

        os.replace(
            temporary,
            final_directory,
        )

    except OSError as exc:
        raise IntelligenceUpdatePromotionError(
            "Failed to promote verified intelligence bundle."
        ) from exc

    finally:
        if temporary.exists():
            shutil.rmtree(
                temporary,
                ignore_errors=True,
            )

    return final_directory


def _load_verification_metadata(
    cache_directory: Path,
) -> IntelligenceUpdateVerificationMetadata:
    path = cache_directory / VERIFICATION_METADATA_FILENAME

    try:
        data = json.loads(path.read_text(encoding="utf-8"))

        metadata = IntelligenceUpdateVerificationMetadata.model_validate(data)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise IntelligenceVerifiedCacheError(
            f"Verified cache metadata is missing, malformed, or unsupported: {cache_directory}."
        ) from exc

    if metadata.metadata_version != 1:
        raise IntelligenceVerifiedCacheError("Unsupported verified-cache metadata version.")

    return metadata


def inspect_verified_cache_entry(
    cache_directory: Path | str,
) -> IntelligenceVerifiedCacheEntry:
    """
    Inspect cached bytes without assigning trust.

    verification.json is checked for consistency but is never accepted
    as cryptographic or lifecycle authority.
    """

    directory = Path(cache_directory)

    if not directory.is_dir():
        raise IntelligenceVerifiedCacheError(
            f"Verified cache entry is not a directory: {directory}."
        )

    policy_path = directory / VERIFIED_POLICY_FILENAME

    manifest_path = directory / VERIFIED_MANIFEST_FILENAME

    try:
        policy_bytes = policy_path.read_bytes()

        manifest_bytes = manifest_path.read_bytes()

        policy = load_policy(policy_path)

        manifest = load_manifest(manifest_path)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise IntelligenceVerifiedCacheError(
            "Verified cache entry contains unreadable or invalid "
            f"policy/manifest data: {directory}."
        ) from exc

    digest = policy_sha256(policy)

    if (
        manifest.policy_id != policy.policy_id
        or manifest.schema_version != policy.schema_version
        or manifest.policy_sha256 != digest
    ):
        raise IntelligenceVerifiedCacheError(
            "Verified cache policy and manifest identity do not match."
        )

    if manifest.generation is None:
        raise IntelligenceVerifiedCacheError(
            "Verified cache manifest lacks a lifecycle generation."
        )

    metadata = _load_verification_metadata(directory)

    metadata_consistent = (
        metadata.policy_id == policy.policy_id
        and metadata.policy_sha256 == digest
        and metadata.manifest_version == manifest.manifest_version
        and metadata.generation == manifest.generation
        and metadata.signer_id == manifest.signer_id
    )

    if not metadata_consistent:
        raise IntelligenceVerifiedCacheError(
            "Verified cache descriptive metadata is inconsistent "
            "with the cached policy or manifest."
        )

    bundle_digest = _sha256_bytes(policy_bytes + b"\x00" + manifest_bytes)

    return IntelligenceVerifiedCacheEntry(
        path=str(directory),
        policy_id=(policy.policy_id),
        policy_sha256=digest,
        generation=(manifest.generation),
        manifest_version=(manifest.manifest_version),
        signer_id=(manifest.signer_id),
        bundle_sha256=(bundle_digest),
        verification_metadata_present=True,
        verification_metadata_consistent=True,
    )


def discover_verified_cache(
    verified_root: Path | str,
    *,
    policy_id: str | None = None,
) -> list[IntelligenceVerifiedCacheEntry]:
    """
    Discover structurally valid cache entries.

    Discovery proves cache consistency only. It does not establish
    signer trust or lifecycle acceptance.
    """

    root = Path(verified_root)

    if not root.exists():
        return []

    if not root.is_dir():
        raise IntelligenceVerifiedCacheError(f"Verified cache root is not a directory: {root}.")

    entries: list[IntelligenceVerifiedCacheEntry] = []

    for directory in sorted(
        (item for item in root.iterdir() if (item.is_dir() and not item.name.startswith("."))),
        key=lambda item: item.name,
    ):
        entry = inspect_verified_cache_entry(directory)

        if policy_id is not None and entry.policy_id != policy_id:
            continue

        entries.append(entry)

    # Same policy generation may have duplicate directory copies only
    # when their actual policy+manifest bytes are equivalent.
    grouped: dict[
        tuple[str, int],
        set[str],
    ] = {}

    for entry in entries:
        key = (
            entry.policy_id,
            entry.generation,
        )

        grouped.setdefault(
            key,
            set(),
        ).add(entry.bundle_sha256)

    for (
        cached_policy_id,
        generation,
    ), bundle_digests in grouped.items():
        if len(bundle_digests) > 1:
            raise IntelligenceVerifiedCacheError(
                "Conflicting verified-cache entries exist for "
                f"policy {cached_policy_id!r} generation {generation}."
            )

    return sorted(
        entries,
        key=lambda entry: (
            entry.policy_id,
            -entry.generation,
            entry.policy_sha256,
            entry.bundle_sha256,
            entry.path,
        ),
    )


def select_verified_cache_candidate(
    verified_root: Path | str,
    *,
    policy_id: str | None = None,
) -> IntelligenceVerifiedCacheEntry:
    """
    Deterministically select the highest cached generation.

    If multiple policy IDs exist, the caller must select one explicitly.
    """

    entries = discover_verified_cache(
        verified_root,
        policy_id=policy_id,
    )

    if not entries:
        if policy_id is None:
            raise IntelligenceVerifiedCacheError(
                "No valid verified-cache intelligence entries were found."
            )

        raise IntelligenceVerifiedCacheError(
            f"No valid verified-cache intelligence entry was found for policy {policy_id!r}."
        )

    policy_ids = {entry.policy_id for entry in entries}

    if policy_id is None and len(policy_ids) != 1:
        raise IntelligenceVerifiedCacheError(
            "Verified cache contains multiple policy IDs. Select --policy-id explicitly."
        )

    # Conflict detection already ensures same-generation entries are
    # equivalent. Path order makes duplicate-equivalent selection stable.
    return min(
        entries,
        key=lambda entry: (
            -entry.generation,
            entry.policy_sha256,
            entry.bundle_sha256,
            entry.path,
        ),
    )


def activate_cached_intelligence(
    *,
    cache_directory: Path | str,
    trust_store_path: Path | str,
    lifecycle_state_path: Path | str,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> VerifiedIntelligenceSelection:
    """
    Activate a cache entry through the existing authoritative boundary.

    Cached verification metadata is never used as trust authority.
    """

    directory = Path(cache_directory)

    # Reject structural corruption before entering activation.
    inspect_verified_cache_entry(directory)

    return activate_verified_intelligence(
        policy_path=(directory / VERIFIED_POLICY_FILENAME),
        manifest_path=(directory / VERIFIED_MANIFEST_FILENAME),
        trust_store_path=(trust_store_path),
        lifecycle_state_path=(lifecycle_state_path),
        minimum_generation=(minimum_generation),
        maximum_age_days=(maximum_age_days),
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )


def select_and_activate_cached_intelligence(
    *,
    verified_root: Path | str,
    trust_store_path: Path | str,
    lifecycle_state_path: Path | str,
    policy_id: str | None = None,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> tuple[
    IntelligenceVerifiedCacheEntry,
    VerifiedIntelligenceSelection,
]:
    entry = select_verified_cache_candidate(
        verified_root,
        policy_id=policy_id,
    )

    selection = activate_cached_intelligence(
        cache_directory=(entry.path),
        trust_store_path=(trust_store_path),
        lifecycle_state_path=(lifecycle_state_path),
        minimum_generation=(minimum_generation),
        maximum_age_days=(maximum_age_days),
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )

    return (
        entry,
        selection,
    )
