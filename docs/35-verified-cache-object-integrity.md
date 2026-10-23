# Phase 30 — Verified Cache Object Integrity & Symlink Containment

Phase 30 hardens the verified-intelligence cache against filesystem identity
substitution through symbolic links and non-regular cached artifacts.

## Problem

Earlier cache hardening protected the verified cache root and final promoted
cache directory.

However, cache inspection still consumed the required cached artifacts by
pathname:

- `policy.json`
- `manifest.json`
- `verification.json`

without first proving that each artifact was:

- a direct child of the cache-entry directory;
- not a symbolic link;
- resolvable beneath the cache-entry directory;
- a regular file.

Cache discovery also used directory checks that could follow a symbolic link
to another directory.

The promotion fast path for an already-existing equivalent cache entry could
also compare `policy.json` and `manifest.json` through symbolic links.

## Central artifact validation

Phase 30 introduces a central verified-cache artifact validator.

For each required artifact, PHP Sentinel now requires:

1. the artifact path itself is not a symbolic link;
2. the cache-entry directory resolves successfully;
3. the artifact resolves successfully;
4. the resolved artifact parent is exactly the resolved cache-entry directory;
5. the resolved artifact is a regular file.

Failure of any condition causes verified-cache inspection to fail closed.

## Cache-entry directory identity

`inspect_verified_cache_entry()` now rejects a symbolic-link cache-entry
directory before reading any cached artifacts.

The directory is then resolved before required artifact paths are validated.

## Discovery hardening

Verified-cache discovery no longer follows symbolic-link directories.

A symlink under the verified cache root is not treated as a discoverable cache
entry even when it points to a valid cache directory.

This prevents aliasing or external directory substitution from expanding the
verified-cache namespace.

## Activation hardening

Cached activation already invokes verified-cache inspection before entering the
authoritative activation boundary.

Because Phase 30 centralizes filesystem validation in cache inspection,
activation now inherits the same protections automatically.

A symlinked cached policy, manifest, or verification artifact therefore fails
before current trust and lifecycle activation are evaluated.

## Promotion hardening

When a candidate cache destination already exists, promotion previously
compared cached policy and manifest bytes directly.

Phase 30 now rejects an existing `policy.json` or `manifest.json` if either is a
symbolic link.

The equivalent-entry fast path requires both artifacts to be regular files
before byte-equivalence comparison.

## Security invariants

Phase 30 establishes these invariants:

1. A discovered cache-entry directory is never a symbolic link.
2. Cached `policy.json` is a direct non-symlink regular file.
3. Cached `manifest.json` is a direct non-symlink regular file.
4. Cached `verification.json` is a direct non-symlink regular file.
5. Required cache artifacts resolve beneath the cache-entry directory.
6. Cached activation reuses the same structural validation boundary.
7. Existing-entry promotion rejects symbolic-link policy or manifest files.
8. Cache discovery still proves structure and consistency only; it does not
   create trust authority.
9. `verification.json` remains descriptive metadata only.
10. Trust and lifecycle decisions are still re-evaluated at authoritative
    activation.

## Threat-model boundary

This phase performs pathname and resolved-path checks before file reads.

These checks materially reduce cache substitution through persistent symlinks
and malformed cache objects.

They are not a claim of race-free filesystem access against a hostile local
process capable of replacing filesystem objects between validation and read.

A stronger future boundary could use directory file descriptors and
`openat`/`O_NOFOLLOW`-style semantics where supported.

## Result

The verified-cache read path is now:

`direct cache directory -> validated direct regular artifacts -> structural
inspection -> authoritative trust/lifecycle activation`

rather than:

`directory pathname -> unrestricted artifact pathname reads`
