# Phase 29 — Canonical Signer Identity

Phase 29 removes ambiguity from delegation and revocation history identities by
constraining signer identifiers at the model boundary.

## Problem

Delegation lifecycle state uses composite history keys such as:

`intelligence|<predecessor>|<successor>`

and revocation history extends that identity with delegation sequence and
delegation digest.

Before Phase 29, signer identifiers were only required to be non-empty strings.

That allowed identities containing the history delimiter itself.

For example, these distinct signer tuples:

- predecessor `a|b`, successor `c`
- predecessor `a`, successor `b|c`

both serialized to:

`intelligence|a|b|c`

The ambiguity existed in both intelligence and source-registry lifecycle
history.

## Design decision

Phase 29 hardens signer identity at the model boundary instead of changing the
persisted history-key format.

Canonical signer IDs now use:

`^[A-Za-z0-9][A-Za-z0-9._-]*$`

with a maximum length of 128 characters.

This matches the bounded identifier style already used elsewhere in PHP
Sentinel.

## Why model-boundary hardening

Changing the lifecycle history-key serialization would require migration of
already persisted delegation and revocation history.

Constraining signer IDs prevents ambiguous future identities while preserving
the existing history layout for canonical signer IDs such as:

- `old`
- `new`
- `registry-signer`
- `signer_01`
- `signer.v2`

The previously valid canonical history keys therefore retain their existing
representation.

## Hardened identity surfaces

Canonical signer identity is enforced for:

- `SignerDelegation.predecessor_signer_id`;
- `SignerDelegation.successor_signer_id`;
- `SignerDelegationRevocation.predecessor_signer_id`;
- `SignerDelegationRevocation.successor_signer_id`;
- `IntelligenceManifest.signer_id`;
- `TrustedSigner.signer_id`;
- `LifecycleStateRecord.signer_id`;
- `SourceRegistryManifest.signer_id`;
- `SourceRegistryStateRecord.signer_id`;
- source-registry `allowed_signer_ids`.

This ensures the same signer identity grammar is used across trust,
authorization, registry selection, and persistent lifecycle state.

## Rejected identity examples

The canonical grammar rejects identities such as:

- `old|new`
- `a|b|c`
- `|`
- `../signer`
- `signer/name`
- identities containing spaces
- `.`
- `..`
- identifiers longer than 128 characters

These values are not required for signer semantics and can create ambiguity,
path-like interpretation, or unbounded state identities.

## Accepted identity examples

Examples that remain valid include:

- `old`
- `new`
- `Signer01`
- `signer-01`
- `signer_01`
- `signer.v1`

## Security effect

Because the history delimiter `|` cannot occur in a signer identity, composite
delegation keys become unambiguous for valid model instances.

The mapping:

`(context, predecessor_signer_id, successor_signer_id)`

to:

`context|predecessor_signer_id|successor_signer_id`

is therefore injective under the canonical signer grammar.

The same property applies to revocation history keys that append sequence and
digest fields.

## Persistent-state validation

Phase 29 also applies canonical signer validation when loading lifecycle state.

A state file containing an ambiguous signer identity is rejected rather than
being interpreted through an unsafe composite history key.

This applies independently to:

- intelligence lifecycle state;
- source-registry lifecycle state.

## Source registry consistency

`allowed_signer_ids` now follows the same canonical signer identity rules as
the actual trust-store signer models.

This prevents a source registry from declaring signer identities that cannot
exist as valid trusted signers.

## Compatibility

No lifecycle state version is changed.

Existing canonical signer IDs remain valid.

Existing persisted state using canonical IDs continues to parse without
migration.

State containing previously accepted noncanonical signer IDs will now fail
closed during model validation.

## Security invariants

Phase 29 adds these invariants:

1. Signer identifiers use one canonical grammar across trust and lifecycle
   models.
2. Signer IDs cannot contain the delegation-history delimiter.
3. Delegation and revocation history keys cannot collide through signer-ID
   delimiter injection.
4. Persistent lifecycle state rejects ambiguous signer identities.
5. Source `allowed_signer_ids` cannot reference noncanonical signer identities.
6. Existing canonical lifecycle-history representation is preserved.
7. No persisted-state migration is required for canonical existing state.

## Result

The history identity path is now:

`canonical signer identity -> unambiguous composite lifecycle key`

rather than:

`arbitrary signer string -> delimiter-dependent history identity`
