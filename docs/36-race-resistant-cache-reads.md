# Phase 31 — Race-Resistant Verified Cache Reads

Phase 31 hardens verified-cache activation against pathname substitution races
that remain possible after ordinary symlink and resolved-path validation.

## Problem

Phase 30 established strong pathname-level cache invariants:

- cache-entry directories must not be symbolic links;
- `policy.json`, `manifest.json`, and `verification.json` must be direct,
  non-symlink regular files;
- cache artifacts must resolve beneath the cache entry;
- cached activation re-runs structural inspection before trust/lifecycle
  activation.

However, cache inspection and activation still involved separate pathname
opens.

A local process able to mutate the filesystem could potentially replace an
artifact after inspection but before a later pathname-based read.

The most important remaining instance was cached activation:

1. inspect cached policy and manifest;
2. close those reads;
3. invoke authoritative activation with policy/manifest paths;
4. authoritative activation opens the paths again.

That is a classic validate-then-use filesystem race.

## Platform capability

On supported POSIX platforms such as Linux/WSL, PHP Sentinel now uses:

- `os.open`
- `dir_fd`
- `O_DIRECTORY`
- `O_NOFOLLOW`
- `O_CLOEXEC`
- `os.fstat`

for the verified-cache read boundary.

## Directory-descriptor boundary

A verified cache entry is first opened as a directory descriptor.

The directory open requires:

- no symbolic-link traversal when `O_NOFOLLOW` is available;
- directory semantics through `O_DIRECTORY` when available;
- descriptor validation with `fstat`.

The descriptor becomes the authority for opening required child artifacts.

## Descriptor-relative artifact reads

Required cache artifacts are opened relative to the already-open directory
descriptor:

- `policy.json`
- `manifest.json`
- `verification.json`

Each artifact open uses `O_NOFOLLOW` where available and is validated with
`fstat` as a regular file.

The artifact is then read from that exact open file descriptor.

This removes the earlier sequence of:

`validate pathname -> later reopen pathname`

for verified-cache inspection.

## Symlink failure semantics

On Linux, opening a symlink with `O_NOFOLLOW` commonly fails with `ELOOP`.

PHP Sentinel maps that result back to the existing explicit verified-cache
symbolic-link error.

This preserves the Phase 30 fail-closed semantics while using the stronger
descriptor-based read primitive.

## Parse-from-bytes boundary

Phase 31 introduces parsing helpers for already-read immutable byte snapshots:

- policy bytes -> validated `IntelligencePolicy`
- manifest bytes -> validated `IntelligenceManifest`

The ordinary pathname loaders now delegate to the same parsing logic.

This avoids duplicating policy or manifest validation semantics.

## Object-based authoritative activation

The authoritative activation logic is now reusable for already-loaded policy
and manifest objects.

The object-based activation path still re-evaluates:

- current local TrustStore;
- Ed25519 manifest signature;
- signer enablement;
- delegation evidence;
- delegation revocations;
- lifecycle state;
- minimum generation;
- freshness and expiry;
- rollback rules;
- signer rotation rules;
- persistent lifecycle mutation.

No caller-supplied trust or lifecycle decision is accepted as authority.

## Cached activation

Cached activation now performs:

1. open verified cache directory safely;
2. open required artifacts relative to that directory descriptor;
3. read exact policy, manifest, and verification bytes;
4. validate structural and transport-metadata consistency;
5. parse the exact policy and manifest byte snapshots;
6. pass those exact objects into authoritative trust/lifecycle activation.

The cache policy and manifest paths are no longer reopened by authoritative
activation.

This closes the main cache-specific validate-then-reopen race.

## Trust invariants retained

Phase 31 does not change the trust model.

In particular:

- `verification.json` remains descriptive only;
- cached discovery does not create trust;
- current TrustStore remains authoritative;
- signatures are reverified during activation;
- delegation authority remains cryptographic and context-bound;
- lifecycle state remains authoritative for rollback/freshness decisions;
- cache transport hashes remain consistency/provenance evidence, not publisher
  authenticity.

## Remaining local-filesystem limits

This phase materially strengthens cache reads but does not claim complete
protection against every hostile-local-process race.

For example:

- the cache directory pathname itself must still be resolved/opened before the
  descriptor exists;
- other non-cache authority files such as TrustStore and lifecycle state retain
  their own storage boundaries;
- platform behavior differs where `O_NOFOLLOW` or directory-relative opens are
  unavailable.

Future hardening may extend descriptor-relative or equivalent primitives to
additional local trust-state objects where justified.

## Result

The verified-cache activation path is now conceptually:

`cache path -> open directory FD -> openat-style no-follow artifact FDs ->
exact byte snapshots -> structural verification -> authoritative
trust/lifecycle activation of those exact objects`

instead of:

`pathname validation -> pathname reads -> later pathname reopen during
activation`
