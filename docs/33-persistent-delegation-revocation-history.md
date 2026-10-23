# Phase 28 — Persistent Delegation Revocation History

Phase 28 makes verified delegation revocations durable across trust-store
changes.

## Objective

Earlier phases provided:

- signed signer delegations;
- signed delegation revocations;
- highest-sequence fail-closed delegation selection;
- persistent delegation sequence and digest history;
- separate intelligence and registry rotation contexts.

Before Phase 28, revocation enforcement depended on revocation evidence being
present in the current `TrustStore`.

If a previously observed revocation later disappeared from operator-provided
trust-store content, the lifecycle state did not independently remember that
the exact delegation had been revoked.

Phase 28 closes that gap.

## Read-only verification invariant

Ordinary verification remains read-only.

These operations do not advance revocation history merely by inspecting data:

- manifest verification;
- source-registry verification;
- staging;
- verified-cache inspection;
- lifecycle evaluation.

Durable revocation state is recorded only at an authoritative activation
boundary.

## Revocation observation

At activation, PHP Sentinel inspects the current trust store for signed
revocations that:

- match the expected trust context;
- match the successor signer;
- identify an exact delegation sequence;
- identify the exact delegation SHA-256;
- verify under the enabled predecessor signer key;
- are not future-issued.

Only cryptographically verified revocation evidence is eligible for durable
observation.

## Persistent revocation record

Lifecycle state stores now include `revocation_records`.

Each record binds:

- delegation sequence;
- delegation SHA-256;
- revocation sequence;
- revocation SHA-256;
- observation time.

The revocation digest covers the signed revocation payload plus its signature.

The digest therefore identifies the exact signed revocation object.

## Canonical revocation identity

Persistent revocation keys bind:

- context;
- predecessor signer;
- successor signer;
- delegation sequence;
- delegation SHA-256.

This makes revocation persistence specific to one exact delegation rather than
to a signer pair in general.

Intelligence and registry records remain context-separated.

## Durable fail-closed behavior

Once a valid revocation has been observed and persisted, lifecycle evaluation
rejects the exact delegation even if the current trust store no longer contains
the revocation.

This prevents revocation disappearance from restoring previously revoked
rotation authority.

The system therefore treats an observed revocation as monotonic security state.

## Revocation sequence rollback protection

For a previously recorded exact delegation revocation:

- a lower revocation sequence is rejected;
- the same revocation sequence with a different revocation digest is rejected;
- the same sequence with the same digest is idempotent;
- a higher valid sequence may replace the earlier record.

This mirrors the existing fail-closed delegation-history design.

## Intelligence activation

External intelligence activation:

1. verifies the intelligence policy and manifest;
2. loads current lifecycle state;
3. re-loads the current trust store at the authoritative activation boundary;
4. resolves valid signed revocations for the intelligence signer;
5. durably records valid revocation evidence;
6. evaluates lifecycle state against the updated revocation history;
7. refuses revoked rotation authority;
8. records accepted lifecycle state only if activation remains valid.

A revoked rotation can therefore cause revocation state to advance while the
intelligence activation itself is denied.

## Source-registry activation

Signed source-registry activation follows the same rule:

1. verify registry signature trust;
2. load current registry lifecycle state;
3. resolve valid registry-context delegation revocations;
4. persist verified revocation evidence;
5. evaluate registry lifecycle state against the updated history;
6. deny the revoked rotation;
7. commit accepted registry lifecycle state only for an activatable registry.

`verify_signed_source_registry()` remains read-only.

Mutation belongs to `activate_signed_source_registry()`.

## Trust semantics

Persistent revocation state does not create new cryptographic trust.

It records a previously verified negative authorization fact.

The local `TrustStore` remains the cryptographic authority for validating newly
observed revocation evidence.

Lifecycle state then preserves the security consequence of that verified
evidence.

## Security invariants

Phase 28 adds these invariants:

1. Verification remains read-only.
2. Revocation persistence occurs only at authoritative activation boundaries.
3. Only cryptographically valid revocations are persisted.
4. Revocation state is bound to an exact delegation digest and sequence.
5. A persisted revocation remains effective even if current trust-store
   revocation evidence disappears.
6. Lower revocation sequences cannot replace higher observed sequences.
7. Same-sequence different-digest revocations fail closed.
8. Intelligence and registry revocation histories remain context-separated.
9. Persisted revocation state does not replace signer trust verification.
10. A denied activation may still durably record valid revocation evidence.

## Result

The rotation trust path now has monotonic revocation memory:

`delegation authority -> valid signed revocation -> authoritative observation -> durable revocation history`

while preserving the core architecture rule:

`verification != lifecycle mutation`
