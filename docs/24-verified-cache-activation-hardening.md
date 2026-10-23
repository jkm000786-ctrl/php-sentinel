# Phase 19 — Verified Cache & Activation Integration Hardening

Phase 19 hardens the boundary between the Phase 18 verified cache and
the existing PHP Sentinel activation authority.

## Core rule

A verified-cache entry is not an activation capability.

The cache proves only that a bundle was verified at an earlier point in
time and copied into the local verified-cache area.

Current trust and lifecycle state remain authoritative.

## Cache inspection

Cache discovery parses the actual:

- `policy.json`,
- `manifest.json`,
- `verification.json`.

The policy digest is recomputed.

The manifest policy identity and digest must match the actual policy.

Descriptive verification metadata must match the actual policy ID,
policy digest, manifest version, generation, and signer ID.

Malformed or inconsistent entries fail closed.

## verification.json is descriptive only

`verification.json` is never used to establish:

- signer trust,
- signature validity,
- lifecycle acceptance,
- activation authority.

Fields such as `trusted` and `activatable` describe the historical
verification event only.

They are not consumed as current authorization decisions.

## Deterministic discovery

Cache discovery sorts entries deterministically.

Candidate selection chooses the highest generation for the requested
policy.

If equivalent copies of the same policy generation exist, stable path
ordering selects one deterministically.

## Conflict detection

Two cache entries for the same policy ID and generation are accepted
only when their actual policy and manifest bytes are equivalent.

Different bundle fingerprints for the same policy generation are a
cache conflict and fail closed.

This prevents ambiguous candidate selection.

## Multiple policy IDs

If the verified cache contains more than one policy ID, automatic
selection is refused unless the operator explicitly supplies the policy
ID.

PHP Sentinel does not guess which intelligence family should become
active.

## Activation

Cache activation delegates to the existing
`activate_verified_intelligence()` function.

That path re-loads:

- cached policy,
- cached manifest,
- current local trust store,
- current lifecycle state.

It then re-runs:

- policy schema validation,
- manifest digest validation,
- Ed25519 signature verification,
- enabled signer lookup,
- freshness checks,
- expiry checks,
- minimum generation checks,
- signer pin / rotation checks,
- rollback checks,
- replay checks.

Only after those checks succeed may lifecycle acceptance state advance.

## Time-of-check behavior

A bundle may be valid when downloaded and cached but invalid later.

Examples include:

- signer removed from the local trust store,
- manifest expiration,
- newer generation already accepted,
- signer rotation state changed,
- operator minimum generation increased.

Cache activation therefore always re-verifies current state.

## Security boundary

Cache inspection is not proof that a target is vulnerable.

Cache activation is not authorization to perform active security
testing.

The verified intelligence system changes vulnerability knowledge used
for assessment. It does not change PHP Sentinel's target authorization
or exploit-safety model.
