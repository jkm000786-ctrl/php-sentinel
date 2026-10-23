from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from php_sentinel.intelligence.activation import (
    VerifiedIntelligenceSelection,
)
from php_sentinel.intelligence.update import (
    IntelligenceUpdateError,
    VerifiedUpdateCandidate,
    _write_json,
    activate_cached_intelligence,
    discover_verified_cache,
    load_stage_metadata,
    promote_verified_candidate,
    stage_remote_bundle,
    verify_staged_bundle,
)
from php_sentinel.models.intelligence_source import (
    IntelligenceSource,
    IntelligenceSourceChannel,
    IntelligenceSourceRegistry,
    IntelligenceSourceSelection,
)
from php_sentinel.models.intelligence_update import (
    IntelligenceUpdateStageMetadata,
    IntelligenceVerifiedCacheEntry,
)


class IntelligenceSourceRegistryError(IntelligenceUpdateError):
    """Raised when source/channel policy fails closed."""


def load_source_registry(
    path: Path | str,
) -> IntelligenceSourceRegistry:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))

        return IntelligenceSourceRegistry.model_validate(data)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise IntelligenceSourceRegistryError(
            "Intelligence source registry is unreadable or invalid."
        ) from exc


def _resolve_source(
    registry: IntelligenceSourceRegistry,
    source_id: str,
) -> IntelligenceSource:
    source = next(
        (item for item in registry.sources if item.source_id == source_id),
        None,
    )

    if source is None:
        raise IntelligenceSourceRegistryError(f"Unknown intelligence source {source_id!r}.")

    if not source.enabled:
        raise IntelligenceSourceRegistryError(f"Intelligence source {source_id!r} is disabled.")

    return source


def _resolve_channel(
    source: IntelligenceSource,
    channel: str,
) -> IntelligenceSourceChannel:
    selected = next(
        (item for item in source.channels if item.channel == channel),
        None,
    )

    if selected is None:
        raise IntelligenceSourceRegistryError(
            f"Unknown channel {channel!r} for source {source.source_id!r}."
        )

    if not selected.enabled:
        raise IntelligenceSourceRegistryError(
            f"Channel {channel!r} for source {source.source_id!r} is disabled."
        )

    return selected


_STRUCTURAL_PATH_ESCAPE_RE = re.compile(
    r"%(?:2e|2f|5c|25)",
    re.IGNORECASE,
)


def _path_is_structurally_safe(
    path: str,
) -> bool:
    """
    Reject path representations whose decoding could alter hierarchy.

    Encoded dot, slash, backslash, or percent bytes are rejected so nested
    encodings cannot turn an apparently contained path into traversal.
    """

    if "\\" in path:
        return False

    if _STRUCTURAL_PATH_ESCAPE_RE.search(path):
        return False

    segments = path.split("/")

    return all(segment not in {".", ".."} for segment in segments)


def _effective_url_port(
    *,
    scheme: str,
    port: int | None,
) -> int | None:
    if port is not None:
        return port

    if scheme == "https":
        return 443

    if scheme == "http":
        return 80

    return None


def _url_is_within_source_base(
    *,
    base_url: str,
    candidate_url: str,
) -> bool:
    """
    Return True only when candidate_url remains structurally contained
    within base_url.

    Containment requires exact scheme, normalized hostname, effective
    port, and a path beneath the configured base path. Credentials,
    query strings, and fragments are rejected.
    """

    base = urlsplit(base_url)
    candidate = urlsplit(candidate_url)

    if base.scheme.lower() != candidate.scheme.lower():
        return False

    if "%" in (base.hostname or "") or "%" in (candidate.hostname or ""):
        return False

    if (base.hostname or "").lower() != (candidate.hostname or "").lower():
        return False

    try:
        base_port = base.port
        candidate_port = candidate.port
    except ValueError:
        return False

    if _effective_url_port(
        scheme=base.scheme.lower(),
        port=base_port,
    ) != _effective_url_port(
        scheme=candidate.scheme.lower(),
        port=candidate_port,
    ):
        return False

    if (
        base.username is not None
        or base.password is not None
        or candidate.username is not None
        or candidate.password is not None
    ):
        return False

    if base.query or base.fragment or candidate.query or candidate.fragment:
        return False

    base_path = base.path or "/"
    candidate_path = candidate.path or "/"

    if not _path_is_structurally_safe(base_path) or not _path_is_structurally_safe(candidate_path):
        return False

    if not base_path.endswith("/"):
        base_path += "/"

    return candidate_path.startswith(base_path)


def resolve_source_selection(
    *,
    registry: IntelligenceSourceRegistry,
    source_id: str,
    channel: str,
) -> IntelligenceSourceSelection:
    source = _resolve_source(
        registry,
        source_id,
    )

    selected_channel = _resolve_channel(
        source,
        channel,
    )

    policy_url = urljoin(
        source.base_url,
        selected_channel.policy_path,
    )

    manifest_url = urljoin(
        source.base_url,
        selected_channel.manifest_path,
    )

    base = source.base_url

    if not _url_is_within_source_base(
        base_url=base,
        candidate_url=policy_url,
    ) or not _url_is_within_source_base(
        base_url=base,
        candidate_url=manifest_url,
    ):
        raise IntelligenceSourceRegistryError(
            "Resolved source-channel URL escaped its configured base URL."
        )

    return IntelligenceSourceSelection(
        source_id=source.source_id,
        channel=selected_channel.channel,
        policy_url=policy_url,
        manifest_url=manifest_url,
        allowed_signer_ids=list(source.allowed_signer_ids),
        minimum_generation=(selected_channel.minimum_generation),
    )


def stage_registry_bundle_from_registry(
    *,
    registry: IntelligenceSourceRegistry,
    source_id: str,
    channel: str,
    staging_directory: Path | str,
    timeout_seconds: float = 15.0,
    maximum_bytes: int = 2 * 1024 * 1024,
    client: httpx.Client | None = None,
    resolver=None,
    peer_address_getter=None,
    now: datetime | None = None,
) -> IntelligenceUpdateStageMetadata:
    """
    Stage a remote intelligence bundle from an already loaded registry.

    This function assigns no authenticity to ``registry`` by itself.
    Callers that require publisher-authenticated source policy must pass
    the registry object obtained from ``VerifiedSourceRegistry``.
    """

    selection = resolve_source_selection(
        registry=registry,
        source_id=source_id,
        channel=channel,
    )

    metadata = stage_remote_bundle(
        policy_url=selection.policy_url,
        manifest_url=(selection.manifest_url),
        staging_directory=(staging_directory),
        timeout_seconds=(timeout_seconds),
        maximum_bytes=(maximum_bytes),
        client=client,
        **({} if resolver is None else {"resolver": resolver}),
        **({} if peer_address_getter is None else {"peer_address_getter": (peer_address_getter)}),
        now=now,
    )

    metadata = metadata.model_copy(
        update={
            "source_id": source_id,
            "channel": channel,
        }
    )

    _write_json(
        Path(staging_directory) / "stage-metadata.json",
        metadata.model_dump(mode="json"),
    )

    return metadata


def stage_registry_bundle(
    *,
    registry_path: Path | str,
    source_id: str,
    channel: str,
    staging_directory: Path | str,
    timeout_seconds: float = 15.0,
    maximum_bytes: int = 2 * 1024 * 1024,
    client: httpx.Client | None = None,
    resolver=None,
    peer_address_getter=None,
    now: datetime | None = None,
) -> IntelligenceUpdateStageMetadata:
    """
    Stage using an explicitly operator-local raw registry file.

    The registry loaded here is configuration, not publisher-authenticated
    registry authority. Remote authenticated workflows should use the
    signed-registry boundary instead.
    """

    registry = load_source_registry(registry_path)

    return stage_registry_bundle_from_registry(
        registry=registry,
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


def _validate_staged_source_identity(
    *,
    metadata: IntelligenceUpdateStageMetadata,
    selection: IntelligenceSourceSelection,
) -> None:
    if metadata.source_id != selection.source_id or metadata.channel != selection.channel:
        raise IntelligenceSourceRegistryError(
            "Staged intelligence source/channel provenance does not "
            "match the selected registry entry."
        )

    if (
        metadata.policy_url != selection.policy_url
        or metadata.manifest_url != selection.manifest_url
    ):
        raise IntelligenceSourceRegistryError(
            "Staged intelligence URLs do not match the selected source/channel registry policy."
        )


def verify_registry_staged_bundle_from_registry(
    *,
    registry: IntelligenceSourceRegistry,
    source_id: str,
    channel: str,
    staging_directory: Path | str,
    trust_store_path: Path | str,
    lifecycle_state_path: Path | str,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> VerifiedUpdateCandidate:
    """
    Verify staged intelligence against an already loaded registry.

    Registry authenticity is a property of the caller's capability, not
    of this model object. Signed workflows must supply the registry from
    ``VerifiedSourceRegistry``.
    """

    selection = resolve_source_selection(
        registry=registry,
        source_id=source_id,
        channel=channel,
    )

    metadata = load_stage_metadata(staging_directory)

    _validate_staged_source_identity(
        metadata=metadata,
        selection=selection,
    )

    effective_minimum = max(
        minimum_generation,
        selection.minimum_generation,
    )

    candidate = verify_staged_bundle(
        staging_directory=(staging_directory),
        trust_store_path=(trust_store_path),
        lifecycle_state_path=(lifecycle_state_path),
        minimum_generation=(effective_minimum),
        maximum_age_days=(maximum_age_days),
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )

    if candidate.manifest.signer_id not in selection.allowed_signer_ids:
        raise IntelligenceSourceRegistryError(
            f"Manifest signer is trusted globally but is not authorized for source {source_id!r}."
        )

    return candidate


def verify_registry_staged_bundle(
    *,
    registry_path: Path | str,
    source_id: str,
    channel: str,
    staging_directory: Path | str,
    trust_store_path: Path | str,
    lifecycle_state_path: Path | str,
    minimum_generation: int = 1,
    maximum_age_days: int = 30,
    maximum_future_skew_seconds: int = 300,
    now: datetime | None = None,
) -> VerifiedUpdateCandidate:
    """
    Verify using an explicitly operator-local raw registry file.

    This path intentionally preserves Phase 20 local configuration
    semantics. It does not claim registry publisher authenticity.
    """

    registry = load_source_registry(registry_path)

    return verify_registry_staged_bundle_from_registry(
        registry=registry,
        source_id=source_id,
        channel=channel,
        staging_directory=staging_directory,
        trust_store_path=trust_store_path,
        lifecycle_state_path=lifecycle_state_path,
        minimum_generation=minimum_generation,
        maximum_age_days=maximum_age_days,
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )


def promote_registry_candidate(
    *,
    candidate: VerifiedUpdateCandidate,
    verified_root: Path | str,
    expected_source_id: str,
    expected_channel: str,
) -> Path:
    if (
        candidate.verification_metadata.source_id != expected_source_id
        or candidate.verification_metadata.channel != expected_channel
    ):
        raise IntelligenceSourceRegistryError(
            "Verified candidate source/channel does not match the requested registry selection."
        )

    return promote_verified_candidate(
        candidate=candidate,
        verified_root=verified_root,
    )


def discover_registry_cache(
    *,
    verified_root: Path | str,
    source_id: str,
    channel: str,
    policy_id: str | None = None,
) -> list[IntelligenceVerifiedCacheEntry]:
    entries = discover_verified_cache(
        verified_root,
        policy_id=policy_id,
    )

    return [
        entry for entry in entries if (entry.source_id == source_id and entry.channel == channel)
    ]


def select_registry_cache_candidate(
    *,
    verified_root: Path | str,
    source_id: str,
    channel: str,
    policy_id: str | None = None,
) -> IntelligenceVerifiedCacheEntry:
    entries = discover_registry_cache(
        verified_root=verified_root,
        source_id=source_id,
        channel=channel,
        policy_id=policy_id,
    )

    if not entries:
        raise IntelligenceSourceRegistryError(
            "No verified-cache entry exists for the selected "
            f"source={source_id!r} channel={channel!r}."
        )

    policy_ids = {entry.policy_id for entry in entries}

    if policy_id is None and len(policy_ids) != 1:
        raise IntelligenceSourceRegistryError(
            "Selected source/channel contains multiple policy IDs. Specify policy_id explicitly."
        )

    # Existing cache discovery already fails closed on conflicts.
    selected = min(
        entries,
        key=lambda entry: (
            -entry.generation,
            entry.policy_sha256,
            entry.bundle_sha256,
            entry.path,
        ),
    )

    return selected


def activate_registry_cached_intelligence_from_registry(
    *,
    registry: IntelligenceSourceRegistry,
    source_id: str,
    channel: str,
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
    selection = resolve_source_selection(
        registry=registry,
        source_id=source_id,
        channel=channel,
    )

    entry = select_registry_cache_candidate(
        verified_root=verified_root,
        source_id=source_id,
        channel=channel,
        policy_id=policy_id,
    )

    if entry.signer_id not in selection.allowed_signer_ids:
        raise IntelligenceSourceRegistryError(
            "Cached signer is not authorized by the selected source."
        )

    effective_minimum = max(
        minimum_generation,
        selection.minimum_generation,
    )

    activated = activate_cached_intelligence(
        cache_directory=entry.path,
        trust_store_path=(trust_store_path),
        lifecycle_state_path=(lifecycle_state_path),
        minimum_generation=(effective_minimum),
        maximum_age_days=(maximum_age_days),
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )

    if activated.trust.signer_id not in selection.allowed_signer_ids:
        raise IntelligenceSourceRegistryError(
            "Activated signer is not authorized by the selected source."
        )

    return (
        entry,
        activated,
    )


def activate_registry_cached_intelligence(
    *,
    registry_path: Path | str,
    source_id: str,
    channel: str,
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
    """
    Activate using an explicitly operator-local raw registry file.

    Signed-registry workflows should use the authenticated boundary in
    ``registry_trust`` instead.
    """

    registry = load_source_registry(registry_path)

    return activate_registry_cached_intelligence_from_registry(
        registry=registry,
        source_id=source_id,
        channel=channel,
        verified_root=verified_root,
        trust_store_path=trust_store_path,
        lifecycle_state_path=lifecycle_state_path,
        policy_id=policy_id,
        minimum_generation=minimum_generation,
        maximum_age_days=maximum_age_days,
        maximum_future_skew_seconds=(maximum_future_skew_seconds),
        now=now,
    )
