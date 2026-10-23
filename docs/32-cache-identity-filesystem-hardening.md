# Phase 27 — Cache Identity & Filesystem Hardening

Phase 27 hardens verified-cache filesystem identity and promotion boundaries.

## Objective

The verified intelligence cache uses policy identity and lifecycle generation to
construct deterministic cache directory names.

Before Phase 27, `policy_id` was only required to be non-empty while cache
promotion interpolated the policy ID directly into a filesystem path.

Phase 27 removes filesystem ambiguity from policy identity and adds independent
path-confinement checks during promotion.

## Canonical policy identity

`IntelligencePolicy.policy_id` and `IntelligenceManifest.policy_id` now use the
same canonical identifier grammar:

`^[A-Za-z0-9][A-Za-z0-9._-]*$`

with a maximum length of 128 characters.

Allowed examples include:

- `php-2026-10-critical`
- `safe-policy`
- `safe_policy.v1`

Rejected examples include:

- `../escape`
- `../../outside`
- `/absolute`
- `nested/name`
- `.`
- `..`
- identifiers containing spaces
- identifiers exceeding 128 characters

The identifier is therefore suitable for deterministic filesystem naming
without path separators, dot-segment traversal, or arbitrary path syntax.

## Manifest identity consistency

The same policy ID constraints are applied to both:

- the intelligence policy; and
- the signed intelligence manifest.

This prevents the policy and manifest layers from accepting different identity
grammars.

## Verified-root resolution

Promotion resolves the configured verified-cache root before constructing the
final destination.

The root must:

- exist after controlled creation;
- resolve successfully; and
- be a directory.

The final cache destination is constructed beneath that resolved root.

Its parent must resolve exactly to the verified root.

A destination whose parent resolves elsewhere fails closed.

## Existing cache destination handling

If the final cache destination already exists, Phase 27 applies additional
filesystem checks before reading cached artifacts.

The destination:

- must not be a symbolic link;
- must resolve successfully;
- must resolve directly beneath the verified root; and
- must be a directory.

Only then may existing policy and manifest bytes be compared for idempotent
promotion.

## Symbolic-link protection

A pre-existing symbolic link at the deterministic cache destination is rejected.

This prevents an attacker-controlled filesystem entry from redirecting cache
promotion or comparison outside the verified root.

The control is independent of policy ID validation.

## Non-directory collision handling

A pre-existing regular file or other non-directory object at the deterministic
cache destination is rejected.

Promotion therefore does not interpret arbitrary filesystem objects as verified
cache entries.

## Temporary promotion directory

Temporary verified-cache directories are created under the resolved verified
root rather than an unresolved caller-supplied path.

This keeps the promotion transaction anchored to the canonical cache root.

## Duplicate semantics

Phase 27 does not change verified-cache duplicate equivalence semantics.

Current behavior remains:

- deterministic cache naming uses policy ID, generation, and policy hash prefix;
- idempotent promotion requires exact existing policy and manifest bytes;
- cache discovery computes a bundle hash over actual policy and manifest bytes;
- conflicting bundles for the same policy ID and generation fail closed.

Semantic-vs-byte equivalence can be evaluated separately in a future phase.

## Security invariants

Phase 27 adds these invariants:

1. Policy IDs cannot contain filesystem path separators.
2. Policy IDs cannot be `.` or `..`.
3. Policy IDs have a bounded canonical grammar.
4. Policy and manifest use the same policy-ID grammar.
5. Verified-cache promotion operates beneath a resolved cache root.
6. Existing final cache paths cannot be symbolic links.
7. Existing final cache paths must resolve directly beneath the verified root.
8. Existing final cache paths must be directories.
9. Temporary promotion directories are created under the resolved verified
   root.
10. Filesystem confinement does not replace cryptographic or lifecycle trust
    verification.

## Result

Verified-cache identity now has two independent protection layers:

`canonical policy identity -> resolved filesystem confinement`

The trust architecture remains unchanged:

`cache presence != intelligence trust`
