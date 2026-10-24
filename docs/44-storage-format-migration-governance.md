# Phase 39 — Storage Format and Migration Governance

## Objective

Phase 39 establishes explicit governance for the local authority storage formats
used by PHP Sentinel.

The governed format axes are:

- lifecycle-state store version;
- source-registry state-store version;
- authority-state authentication-envelope version;
- local authority-key file version.

All four are currently version 1.

## Central format policy

`format_governance.py` is the policy surface for authority format evolution.

Each authority format has:

- an explicit readable-version set;
- one canonical current write version;
- a version disposition;
- an explicit migration registry.

The current write version must be:

- present in the readable-version set;
- the highest readable version.

This prevents an implementation from accidentally declaring an older format as
the canonical write target while also accepting a newer one.

## Version dispositions

A version can be classified as:

- `current`;
- `older_supported`;
- `older_unsupported`;
- `future_unsupported`;
- `invalid`.

`current` is both readable and writable.

`older_supported` is readable for compatibility but not writable without an
explicit migration.

`older_unsupported` and `future_unsupported` fail closed.

Invalid version values also fail closed.

## Readable does not imply writable

Backward-compatible reading must never silently authorize persistence in an old
format.

When future releases add a readable historical version, that version is
expected to be:

- loadable when explicitly supported;
- non-writable through ordinary persistence;
- migrated only through an explicit registered migration.

This avoids silent downgrade persistence.

## Writer boundaries

Current-format enforcement is applied at the actual mutation boundaries:

- lifecycle-state persistence;
- source-registry state persistence;
- authority-state envelope creation;
- authority-key generation.

The ordinary persistence path therefore emits only the canonical current format.

## Existing unsigned-state migration

The existing operations:

- `migrate_lifecycle_state_to_authenticated(...)`;
- `migrate_source_registry_state_to_authenticated(...)`

are not store-version migrations.

They change the storage container from unsigned state to an authenticated
authority-state envelope while preserving the embedded version-1 state store.

They remain explicit operator actions.

## Migration registry

Authority format version-to-version migrations must be explicitly registered.

Phase 39 intentionally registers none because there is currently only one
supported version for each governed format.

A future migration such as lifecycle-state v1 -> v2 must therefore be introduced
as an explicit implementation and registration, rather than inferred from the
fact that both versions happen to be readable.

## Future-version handling

Future versions are never guessed, downgraded, or interpreted as the current
format.

Current loaders already fail closed through their versioned Pydantic models.

Phase 39 pins this behavior with regression tests for:

- future lifecycle-state store versions;
- future source-registry state-store versions;
- future authority-state envelope versions;
- future authority-key file versions.

Recovery diagnostics classify unsupported future local authority artifacts as
malformed/unsupported and never automatically rewrite them.

## Write safety

A future compatibility-readable old version must not be silently written by:

- normal lifecycle mutation;
- registry mutation;
- authenticated envelope creation;
- authority-key generation.

Writers require the current format before filesystem mutation.

## Migration security rules

Future migrations must satisfy all of the following:

1. Explicit source version.
2. Explicit destination version.
3. Source format must be structurally validated before conversion.
4. Destination must be the canonical writable version.
5. No implicit downgrade migration.
6. No future-version guessing.
7. No migration merely because a parser can deserialize the source.
8. Authority history must not be discarded.
9. Authenticated-state migrations must preserve the relevant authentication and
   rollback/revocation security boundary.
10. Filesystem mutation must retain the descriptor-anchored atomic persistence
    model.

## Separation from recovery

Format migration and corruption recovery are distinct security operations.

An unsupported format is not automatically proof of corruption.

Likewise, a corrupt artifact is not a migration candidate merely because a newer
format exists.

Phase 38 recovery semantics continue to apply:

- diagnose;
- preserve;
- fail closed;
- never auto-reset authority history.

## Non-claims

Phase 39 does not yet provide:

- lifecycle-state v1 -> v2 migration;
- registry-state v1 -> v2 migration;
- authority-envelope v1 -> v2 migration;
- key-file v1 -> v2 migration;
- key rotation;
- downgrade conversion;
- automatic migration on read;
- automatic migration on activation.

Those capabilities require explicit future designs.

## Result

PHP Sentinel now has an explicit storage evolution contract:

`readability != writability != migration authority`

Authority formats are versioned, current writes are constrained to the canonical
format, unsupported future formats fail closed, and version-to-version migration
cannot occur without an explicit registered migration path.
