from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from php_sentinel.models.intelligence_lifecycle import (
    SUPPORTED_LIFECYCLE_STATE_STORE_VERSIONS,
)
from php_sentinel.models.registry_trust import (
    SUPPORTED_REGISTRY_STATE_VERSIONS,
)
from php_sentinel.models.state_auth import (
    SUPPORTED_AUTHORITY_STATE_AUTH_VERSIONS,
)
from php_sentinel.models.state_key import (
    SUPPORTED_AUTHORITY_STATE_KEY_FILE_VERSIONS,
)


class AuthorityFormatKind(StrEnum):
    LIFECYCLE_STATE_STORE = "lifecycle_state_store"
    REGISTRY_STATE_STORE = "registry_state_store"
    AUTHORITY_STATE_ENVELOPE = "authority_state_envelope"
    AUTHORITY_KEY_FILE = "authority_key_file"


class FormatVersionDisposition(StrEnum):
    CURRENT = "current"
    OLDER_SUPPORTED = "older_supported"
    OLDER_UNSUPPORTED = "older_unsupported"
    FUTURE_UNSUPPORTED = "future_unsupported"
    INVALID = "invalid"


@dataclass(frozen=True)
class AuthorityFormatPolicy:
    kind: AuthorityFormatKind
    supported_versions: frozenset[int]
    current_write_version: int

    def __post_init__(self) -> None:
        if not self.supported_versions:
            raise ValueError("Authority format policy requires at least one supported version.")

        if any(
            isinstance(version, bool) or not isinstance(version, int) or version < 1
            for version in self.supported_versions
        ):
            raise ValueError("Authority format supported versions must be positive integers.")

        if self.current_write_version not in self.supported_versions:
            raise ValueError("Authority format current write version must also be readable.")

        if self.current_write_version != max(self.supported_versions):
            raise ValueError(
                "Authority format current write version must be the highest supported version."
            )


@dataclass(frozen=True)
class FormatVersionDecision:
    kind: AuthorityFormatKind
    observed_version: int | None
    disposition: FormatVersionDisposition
    readable: bool
    writable: bool
    migration_required: bool
    migration_supported: bool
    supported_versions: tuple[int, ...]
    current_write_version: int
    rationale: str


AUTHORITY_FORMAT_POLICIES = {
    AuthorityFormatKind.LIFECYCLE_STATE_STORE: AuthorityFormatPolicy(
        kind=AuthorityFormatKind.LIFECYCLE_STATE_STORE,
        supported_versions=SUPPORTED_LIFECYCLE_STATE_STORE_VERSIONS,
        current_write_version=max(SUPPORTED_LIFECYCLE_STATE_STORE_VERSIONS),
    ),
    AuthorityFormatKind.REGISTRY_STATE_STORE: AuthorityFormatPolicy(
        kind=AuthorityFormatKind.REGISTRY_STATE_STORE,
        supported_versions=SUPPORTED_REGISTRY_STATE_VERSIONS,
        current_write_version=max(SUPPORTED_REGISTRY_STATE_VERSIONS),
    ),
    AuthorityFormatKind.AUTHORITY_STATE_ENVELOPE: AuthorityFormatPolicy(
        kind=AuthorityFormatKind.AUTHORITY_STATE_ENVELOPE,
        supported_versions=SUPPORTED_AUTHORITY_STATE_AUTH_VERSIONS,
        current_write_version=max(SUPPORTED_AUTHORITY_STATE_AUTH_VERSIONS),
    ),
    AuthorityFormatKind.AUTHORITY_KEY_FILE: AuthorityFormatPolicy(
        kind=AuthorityFormatKind.AUTHORITY_KEY_FILE,
        supported_versions=SUPPORTED_AUTHORITY_STATE_KEY_FILE_VERSIONS,
        current_write_version=max(SUPPORTED_AUTHORITY_STATE_KEY_FILE_VERSIONS),
    ),
}

# Version-to-version authority format migrations must be explicitly registered.
#
# The existing unsigned-state -> authenticated-envelope operation is intentionally
# not represented here because it changes the storage/authentication container,
# not the embedded lifecycle/registry store_version.
AUTHORITY_FORMAT_MIGRATIONS: frozenset[tuple[AuthorityFormatKind, int, int]] = frozenset()


def authority_format_policy(
    kind: AuthorityFormatKind,
) -> AuthorityFormatPolicy:
    return AUTHORITY_FORMAT_POLICIES[kind]


def authority_format_migration_supported(
    kind: AuthorityFormatKind,
    *,
    from_version: int,
    to_version: int,
) -> bool:
    return (
        kind,
        from_version,
        to_version,
    ) in AUTHORITY_FORMAT_MIGRATIONS


def evaluate_authority_format_version(
    kind: AuthorityFormatKind,
    version: object,
) -> FormatVersionDecision:
    policy = authority_format_policy(kind)
    supported = tuple(sorted(policy.supported_versions))
    current = policy.current_write_version

    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        return FormatVersionDecision(
            kind=kind,
            observed_version=None,
            disposition=FormatVersionDisposition.INVALID,
            readable=False,
            writable=False,
            migration_required=False,
            migration_supported=False,
            supported_versions=supported,
            current_write_version=current,
            rationale="Format version must be a positive integer.",
        )

    if version == current:
        return FormatVersionDecision(
            kind=kind,
            observed_version=version,
            disposition=FormatVersionDisposition.CURRENT,
            readable=True,
            writable=True,
            migration_required=False,
            migration_supported=False,
            supported_versions=supported,
            current_write_version=current,
            rationale="Observed version is the canonical current write format.",
        )

    if version in policy.supported_versions:
        migration_supported = authority_format_migration_supported(
            kind,
            from_version=version,
            to_version=current,
        )

        return FormatVersionDecision(
            kind=kind,
            observed_version=version,
            disposition=FormatVersionDisposition.OLDER_SUPPORTED,
            readable=True,
            writable=False,
            migration_required=True,
            migration_supported=migration_supported,
            supported_versions=supported,
            current_write_version=current,
            rationale=(
                "Observed version is readable for compatibility but must not be "
                "silently rewritten as the current format."
            ),
        )

    if version > current:
        return FormatVersionDecision(
            kind=kind,
            observed_version=version,
            disposition=FormatVersionDisposition.FUTURE_UNSUPPORTED,
            readable=False,
            writable=False,
            migration_required=False,
            migration_supported=False,
            supported_versions=supported,
            current_write_version=current,
            rationale=("Observed version is newer than this PHP Sentinel build understands."),
        )

    migration_supported = authority_format_migration_supported(
        kind,
        from_version=version,
        to_version=current,
    )

    return FormatVersionDecision(
        kind=kind,
        observed_version=version,
        disposition=FormatVersionDisposition.OLDER_UNSUPPORTED,
        readable=False,
        writable=False,
        migration_required=True,
        migration_supported=migration_supported,
        supported_versions=supported,
        current_write_version=current,
        rationale=(
            "Observed version is older than the current format but is not in the "
            "explicit readable-version set."
        ),
    )


def require_current_writable_format(
    kind: AuthorityFormatKind,
    version: object,
) -> FormatVersionDecision:
    decision = evaluate_authority_format_version(
        kind,
        version,
    )

    if not decision.writable:
        raise ValueError(
            f"{kind.value} version {version!r} is not writable; "
            f"current write version is {decision.current_write_version}."
        )

    return decision
