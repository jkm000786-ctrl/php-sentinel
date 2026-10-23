# Phase 15 — Policy Lifecycle and Rollback Protection

Phase 15 adds lifecycle authorization after cryptographic trust
verification and before any target interaction.

A valid signature is necessary but is not sufficient for activation.

## Manifest v2

Lifecycle-aware manifests contain:

- policy generation,
- issued time,
- expiration time,
- policy digest,
- signer identity,
- Ed25519 signature.

Manifest v1 remains cryptographically verifiable for compatibility but
does not contain sufficient lifecycle metadata for new external-policy
activation.

## Lifecycle states

PHP Sentinel distinguishes:

- `current`,
- `stale`,
- `expired`,
- `future_issued`,
- `below_minimum_generation`,
- `rollback_detected`,
- `replay_detected`,
- `signer_changed`,
- `legacy_no_lifecycle`.

Only `current` is externally activatable.

## Freshness

External manifests are denied when:

- `issued_at` exceeds allowed future clock skew,
- the manifest has expired,
- the manifest exceeds the configured maximum age.

The default maximum age is 30 days.

## Minimum generation

Operators can require:

`--minimum-policy-generation N`

A correctly signed policy below that generation is still denied.

## Persistent rollback protection

External scans use:

`--lifecycle-state PATH`

The default state location is:

`~/.local/state/php-sentinel/intelligence-lifecycle.json`

For each policy ID PHP Sentinel records:

- highest accepted generation,
- accepted policy SHA-256,
- pinned signer,
- acceptance time.

A lower generation is rejected as:

`rollback_detected`

## Same-generation digest conflict

If an already accepted generation is later presented with a different
policy SHA-256, activation is rejected as:

`replay_detected`

This protects the generation namespace against equivocation or
same-generation content replacement.

Reusing the exact same generation and digest is allowed.

## Signer pinning

The signer associated with the first accepted lifecycle record becomes
the pinned signer for that policy ID.

A different signer is rejected as:

`signer_changed`

Signer rotation therefore requires an explicit operator-controlled
migration instead of silent trust replacement.

## Activation ordering

External activation now follows:

1. policy schema validation,
2. manifest validation,
3. trust-store validation,
4. policy digest validation,
5. Ed25519 signature verification,
6. freshness and expiration checks,
7. minimum-generation check,
8. signer-pin check,
9. rollback/replay check,
10. lifecycle-state persistence,
11. target interaction.

Therefore a signed but stale, expired, rolled-back, replay-conflicting,
or signer-changed policy cannot influence target assessment.

## CLI

Lifecycle controls are available on `php-sentinel scan`:

- `--minimum-policy-generation`,
- `--max-policy-age-days`,
- `--lifecycle-state`.

The existing intelligence activation failure exit code remains `4`.

## Provenance

Unified reports now carry:

- `intelligence_lifecycle_state`,
- `intelligence_generation`,
- `intelligence_issued_at`,
- `intelligence_expires_at`.

The bundled policy is represented as lifecycle `current`. Its lifecycle
is governed by the installed PHP Sentinel package rather than an
external signed manifest.

## Compatibility

The existing:

`activate_intelligence()`

API remains available and returns `(policy, trust)`.

Lifecycle-aware callers can use:

`activate_intelligence_with_lifecycle()`

which returns:

`(policy, trust, lifecycle)`.
