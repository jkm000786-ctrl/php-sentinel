# Phase 23 — Delegation Revocation and Historical Rotation State

Phase 23 hardens PHP Sentinel signer rotation against delegation rollback,
delegation substitution, and explicit revocation.

## Security boundary

The local `TrustStore` remains the root trust anchor.

A delegation never introduces an arbitrary signer key. Both predecessor and
successor signer keys must already exist as enabled local trusted signers.

Delegation remains direct and one-hop only.

## Signed revocation

A delegation can be revoked by a predecessor-signed
`SignerDelegationRevocation`.

Revocation signatures use the independent domain:

`PHP-SENTINEL-SIGNER-DELEGATION-REVOCATION-V1`

A revocation binds:

- context (`intelligence` or `registry`);
- predecessor signer ID;
- successor signer ID;
- delegation sequence;
- exact delegation SHA-256;
- revocation sequence;
- issuance timestamp;
- Ed25519 algorithm.

The revocation therefore targets one exact delegation rather than a loose
signer relationship.

## Canonical delegation digest

`signer_delegation_sha256()` hashes the domain-separated canonical delegation
signing bytes together with the actual delegation signature.

This permits PHP Sentinel to distinguish two delegation objects even when they
claim the same sequence number.

## Highest-sequence fail-closed rule

For each predecessor/successor/context relationship PHP Sentinel selects the
highest presented delegation sequence first.

Only that delegation is evaluated for authority.

If the highest sequence is:

- expired;
- not yet valid;
- cryptographically invalid;
- bound to the wrong key;
- disabled by local trust;
- or validly revoked;

the relationship has no delegation authority.

PHP Sentinel never falls back to an older lower-sequence delegation.

This rule prevents a revoked or invalid newer rotation decision from silently
reactivating an older delegation.

## Historical delegation state

Both lifecycle stores now contain a separate `delegation_records` namespace.

Each record contains:

- highest accepted delegation sequence;
- exact accepted delegation digest;
- acceptance timestamp.

The history key is context-specific:

- `intelligence|predecessor|successor`
- `registry|predecessor|successor`

Intelligence and registry rotation authority remain separate trust domains.

## Lifecycle enforcement

When a signer changes, lifecycle evaluation requires exact verified delegation
evidence.

Against historical delegation state:

- lower sequence is rejected;
- same sequence with another digest is rejected;
- same sequence with the same digest remains acceptable;
- a higher valid sequence may advance rotation state.

Existing content-generation rollback and replay protections remain active.

## Atomic state advancement

Delegation history is not stored in a third persistence subsystem.

For intelligence, the existing hardened intelligence lifecycle transaction
commits both:

- accepted policy generation/signer state;
- accepted delegation sequence/digest state.

For source registries, the existing registry lifecycle transaction commits both:

- accepted registry generation/signer state;
- accepted delegation sequence/digest state.

Existing state protections continue to apply, including locking,
evaluation-to-commit snapshot comparison, atomic replacement, durability
operations, and restricted permissions where supported.

## Verification is read-only

Trust verification and lifecycle evaluation do not advance delegation state.

State advances only through the authoritative acceptance/activation recording
boundary.

## Revocation persistence limitation

A currently supplied and valid signed revocation prevents the targeted
delegation from authorizing rotation.

Phase 23 historical delegation sequence state prevents fallback to previously
accepted lower delegation sequences.

However, revocation objects themselves are not yet maintained as an independent
cryptographically durable revocation-history ledger. Therefore this phase does
not claim that removal of all revocation evidence from operator-controlled trust
configuration is independently detectable solely from revocation history.

That distinction is intentional and must not be overstated.

## Safety scope

Signer delegation and revocation concern intelligence provenance only.

They do not authorize active target testing, exploitation, scanning, or any
other network operation.
