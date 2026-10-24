# Phase 38 — Authority-State Recovery and Corruption Handling

## Objective

Phase 38 defines deterministic recovery semantics for PHP Sentinel's local
authority artifacts without weakening rollback, revocation, signer-history, or
authenticated-state guarantees.

The authority artifacts are:

- intelligence lifecycle state;
- source-registry lifecycle state;
- the local authority-state HMAC key.

The central rule is:

> Corruption is diagnosed, not silently repaired.

## Why automatic reset is unsafe

Lifecycle and registry state are security history, not disposable cache data.

They may contain:

- the highest accepted intelligence generation;
- pinned signer identity;
- delegation history;
- delegation-revocation history;
- source-registry generation history;
- source-registry revocation history.

Deleting, resetting, or replacing corrupted state with an empty store could
erase evidence needed to reject a rollback, replay, revoked delegation, or
unauthorized signer transition.

Therefore malformed or authentication-failed state is not automatically
reinitialized.

## Authority-key creation boundary

Phase 38 distinguishes a genuinely absent local authority key from every other
key-storage failure.

`AuthorityStateKeyNotFoundError` is raised only when the key is actually
missing.

`load_or_create_authority_state_key()` may create a key only after that specific
condition.

It does not attempt replacement when the existing key is:

- malformed;
- unsupported;
- a symbolic link;
- a non-regular object;
- stored beneath an unsafe path;
- otherwise unreadable or unsafe.

Exclusive creation remains the race-control boundary.

## Read-only recovery diagnostics

Phase 38 adds a read-only diagnostic layer for lifecycle state, registry state,
and the authority key.

Lifecycle and registry status can be:

- `missing`;
- `valid_authenticated`;
- `valid_legacy`;
- `authority_key_required`;
- `authentication_failed`;
- `malformed_or_unsupported`;
- `unsafe_storage`.

Authority-key status can be:

- `missing`;
- `valid`;
- `malformed_or_unsupported`;
- `unsafe_storage`.

Every diagnostic currently reports:

`recoverable_automatically = false`

This is intentional.

## Single-snapshot state diagnosis

Lifecycle and registry diagnostics read the authority-state file once through
the existing hardened descriptor-relative storage reader.

The returned byte snapshot is then:

1. decoded as JSON;
2. classified as legacy or authenticated-envelope shaped;
3. schema validated;
4. authenticated when a key is available;
5. validated against the expected embedded state schema.

The diagnostic layer does not perform an initial pathname read followed by a
second authoritative read.

This avoids diagnostic inconsistencies caused by independently resolving the
same pathname twice.

## Authenticated-envelope classification

A valid authenticated envelope without its local authority key is classified as:

`authority_key_required`

It is not treated as legacy state.

An object that merely contains authentication-looking fields but does not
validate as an authority-state envelope is classified as:

`malformed_or_unsupported`

Supplying a key does not cause valid unsigned legacy state to be mislabeled as
corrupt. It remains:

`valid_legacy`

Explicit migration remains a separate operator action.

## Authentication failure

MAC failure, key mismatch, or context mismatch is classified as:

`authentication_failed`

PHP Sentinel does not infer whether the cause was:

- accidental corruption;
- use of the wrong preserved key;
- unauthorized modification;
- an incomplete manual restore.

All of those conditions fail closed.

## Filesystem safety

Recovery diagnosis retains the storage hardening established in earlier phases.

Lifecycle and registry state are read through the descriptor-anchored,
no-follow state readers.

Authority keys are loaded through the anchored key reader.

A symbolic link, non-regular file, or unsafe ancestor is therefore classified as
unsafe storage rather than followed for diagnostic convenience.

## No automatic quarantine

Phase 38 does not automatically rename a corrupt authority file to `.corrupt`,
`.bak`, or another quarantine name.

Renaming the active file and allowing a fresh empty state to appear would
effectively create a security-history reset.

Preserving the damaged artifact is preferable to silently weakening rollback or
revocation protection.

## No implicit key regeneration

A malformed or lost authority key is not automatically replaced when
authenticated state already depends on it.

A new key cannot authenticate historical state created with the lost key.

Generating one implicitly could create a new local trust epoch without an
auditable transition and could orphan existing rollback/revocation history.

## Backup and restore boundary

Phase 38 does not claim that an arbitrary older backup is safe to restore.

An older, otherwise valid authenticated backup may itself contain less rollback
or revocation history than the most recently accepted state.

Without an independent monotonic recovery anchor, PHP Sentinel cannot prove
that an older backup is security-equivalent to the lost current state.

For that reason this phase provides classification and preservation semantics,
not automatic backup rollback.

A future recovery design may add a separately protected monotonic recovery
anchor or coordinated authority-state snapshot protocol.

## Operator recovery principle

When diagnostics report corruption or authentication failure, the safe
operational response is to preserve:

- the damaged authority-state file;
- the corresponding authority-state key;
- any known-good coordinated backups;
- relevant application logs and timestamps.

Recovery must be an explicit operator decision.

PHP Sentinel does not convert a corruption event into a fresh empty authority
history automatically.

## Security invariants

Phase 38 establishes:

1. Missing keys are distinguishable from corrupt or unsafe keys.
2. Only genuine key absence permits load-or-create key generation.
3. Existing malformed keys are never overwritten by load-or-create.
4. Recovery diagnostics are read-only.
5. Diagnostics retain descriptor/no-follow filesystem protections.
6. Lifecycle and registry diagnosis uses one hardened byte snapshot.
7. Authenticated state without its key is never treated as legacy state.
8. Authentication failure never triggers state reset.
9. Valid legacy state remains identifiable even when a key is available.
10. No automatic quarantine creates an implicit empty-history reset.
11. No arbitrary backup is claimed safe merely because its MAC is valid.
12. Recovery classification does not weaken activation's existing fail-closed
    behavior.

## Non-claims

Phase 38 does not provide:

- deletion protection;
- cryptographic monotonic counters outside the authority-state files;
- safe automatic rollback to older backups;
- transparent authority-key rotation;
- reconstruction of lost rollback or revocation history;
- recovery when both state and its independently protected key are compromised.

Those require separate trust anchors or coordinated recovery protocols.

## Result

PHP Sentinel now distinguishes:

`missing -> valid legacy -> valid authenticated -> key required ->
authentication failure -> malformed -> unsafe storage`

without silently mutating the authority artifacts being diagnosed.

Corruption handling therefore remains evidence-preserving and fail-closed rather
than becoming an implicit authority-state reset mechanism.
