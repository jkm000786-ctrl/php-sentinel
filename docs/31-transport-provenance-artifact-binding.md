# Phase 26 — Transport Provenance & Artifact Binding

Phase 26 strengthens the relationship between remote transport observations,
staged artifacts, verified-cache metadata, and current source-registry
authority.

## Objective

Earlier phases already established:

- remote transport containment;
- staged transport digests;
- cryptographic policy-manifest verification;
- lifecycle verification;
- source/channel provenance;
- verified-cache inspection;
- current trust and lifecycle re-verification at activation.

Phase 26 tightens artifact binding without turning descriptive metadata into a
trust capability.

## Staged transport integrity

Stage metadata records:

- policy URL;
- manifest URL;
- policy transport SHA-256;
- manifest transport SHA-256;
- policy byte count;
- manifest byte count;
- source ID and channel when registry-backed.

Phase 26 requires staged verification and promotion to re-check both:

1. exact byte counts; and
2. exact transport digests.

A staged object whose length or digest no longer matches its recorded transport
observation fails closed.

## Verification metadata

`verification.json` remains descriptive metadata.

It is not:

- cryptographic publisher authority;
- signer trust authority;
- lifecycle authority;
- registry authority.

Phase 26 does not change that invariant.

The metadata records the staged source URLs and transport digests so operators
can inspect how the cached bundle entered the system.

## Verified-cache artifact binding

Verified-cache inspection already reparses the policy and manifest and verifies
their internal identity relationship.

Phase 26 additionally requires the recorded staged transport digests to match
the actual cached bytes.

Therefore descriptive verification metadata cannot claim transport digests that
differ from the current cached artifacts.

This is consistency checking only.

It does not authenticate the publisher.

## Current registry provenance

Registry-backed staged verification already requires:

- source ID match;
- channel match;
- exact policy URL match;
- exact manifest URL match.

Before Phase 26, registry-backed cached activation selected entries by source ID
and channel but did not require their recorded source URLs to match the current
registry selection.

Phase 26 closes that gap.

At registry-backed activation, cached:

- `source_policy_url`; and
- `source_manifest_url`

must equal the URLs produced by the current registry source/channel selection.

A cache entry from a prior URL configuration therefore cannot remain eligible
merely because the source ID and channel names are unchanged.

## Registry authority semantics

The source registry still narrows authority.

It does not create cryptographic trust.

Activation still independently re-evaluates:

- current registry authority;
- current signer authorization;
- current local trust store;
- current lifecycle state;
- current minimum generation.

URL provenance is an additional eligibility condition, not a replacement for
those controls.

## Fail-closed behavior

Phase 26 rejects:

- staged policy byte-count mismatch;
- staged manifest byte-count mismatch;
- staged transport digest mismatch;
- cached transport-digest metadata mismatch;
- stale cached source URLs under a changed registry configuration.

These failures happen before the affected artifact can be treated as eligible
for trusted activation.

## Security invariants

Phase 26 adds these invariants:

1. Recorded staged byte counts must match staged artifact bytes.
2. Recorded staged transport digests must match staged artifact bytes.
3. Cached descriptive transport digests must match cached artifact bytes.
4. Registry-backed activation requires cached source URLs to equal the current
   source/channel URL selection.
5. Source/channel labels alone are insufficient provenance for registry-backed
   activation.
6. `verification.json` remains descriptive and is never accepted as a trust
   capability.
7. Trust and lifecycle authority continue to be re-evaluated from their
   authoritative sources.

## Result

The trusted update path now binds transport provenance more tightly across:

`remote fetch -> staging -> verification -> verified cache -> registry-backed activation`

while preserving the architectural rule:

`transport success != intelligence trust`
