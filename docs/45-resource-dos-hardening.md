# Phase 40 — Resource / DoS Hardening

## Purpose

Phase 40 bounds resource consumption at security-sensitive PHP Sentinel
ingress, storage, cache, and persistence boundaries.

The goal is deterministic fail-closed behavior when attacker-controlled or
operator-controlled inputs are excessively large or contain excessive
collection cardinality.

These controls are defense in depth. They are not a claim of absolute
process-memory, CPU, kernel, filesystem, mount-namespace, or operating-system
resource isolation.

## Security properties

### Remote HTTP response bodies

Ordinary target assessment responses are streamed and bounded before a normal
loaded `httpx.Response` is constructed.

Default maximum:

- target HTTP response body: 2 MiB

The limit is enforced both from a trustworthy numeric `Content-Length` when
present and from actual streamed bytes. A missing, malformed, or understated
`Content-Length` therefore cannot bypass the streamed byte limit.

The update channel already uses its own streamed transport boundary:

- remote intelligence artifact: 2 MiB

### Local security-sensitive files

Descriptor-bound readers now cap security-sensitive local files while
retaining regular-file and no-follow semantics where supported.

Limits:

- lifecycle state: 4 MiB
- local authority key file: 64 KiB
- trust store: 4 MiB
- policy / manifest / source-registry local intelligence artifact: 4 MiB
- staged update metadata: 256 KiB
- staged policy: 4 MiB
- staged manifest: 4 MiB
- verified-cache artifact: 4 MiB
- operator-supplied comparison report: 8 MiB

Bounded reads use the same opened descriptor for file-type validation and byte
consumption. This avoids the previous `stat()` followed by pathname re-open
TOCTOU pattern for staged update artifacts.

### Verified cache

Verified-cache artifacts continue to be opened relative to an already-open
cache-directory descriptor with no-follow semantics where available.

Existing cache-entry comparisons during promotion now use the same
descriptor-bound bounded reader instead of direct `Path.read_bytes()` calls.

Cache discovery applies two independent ceilings:

- 2048 visible candidate cache directories;
- 4096 total filesystem entries encountered while scanning the cache root.

The raw filesystem-entry ceiling is evaluated before filtering hidden entries,
non-directories, or symbolic links. This prevents ignored filesystem objects
from forcing an unbounded cache-root scan.

Both ceilings are enforced incrementally during directory iteration rather
than after materializing an arbitrary number of entries.

Discovery remains structural only. It does not establish signer trust or
lifecycle acceptance.

### Comparison report inputs

Baseline comparison reports are operator-supplied local files and are therefore
also treated as bounded runtime input.

Limit:

- comparison report: 8 MiB

Comparison reports are opened with the same regular-file and no-follow
semantics used by other local hardened readers where the platform supports
them. Oversized files are rejected rather than truncated.

### Collection cardinality

Pydantic model boundaries now cap attacker-controlled or persisted security
collections.

Source-registry limits:

- sources: 256
- channels per source: 128
- allowed signers per source: 128

Trust-store limits:

- signers: 512
- delegations: 2048
- delegation revocations: 4096
- authorized predecessors per signer: 128

Lifecycle-state limits:

- policy records: 4096
- delegation-history records: 4096
- revocation-history records: 8192

Source-registry lifecycle-state limits:

- registry records: 1024
- delegation-history records: 4096
- revocation-history records: 8192

These bounds are independent from serialized byte limits. The effective limit
is whichever boundary is reached first.

### Persistence-boundary revalidation

Pydantic `model_copy()` and ordinary mutable collection assignment can bypass
assignment-time validation.

For that reason, lifecycle and source-registry state are revalidated at the
lowest persistence boundary immediately before serialization.

This means:

- public save APIs fail closed on oversized mutated state;
- internal lifecycle mutation paths fail closed;
- delegation-history mutation paths fail closed;
- revocation-history mutation paths fail closed;
- authenticated state persistence receives validated state;
- oversized state is not silently written.

No historical security state is silently pruned to satisfy a limit.

If a cardinality limit would be exceeded, persistence fails instead of
discarding rollback, delegation, or revocation history.

### Path-anchor zero-component correction

A Phase 37 follow-up discovered that zero-component anchors such as `.` and
`/` could reach the final `fchmod()` path even though no child directory had
been traversed.

Phase 40 corrects this by applying the final directory-mode hardening only when
the requested anchor contains at least one traversed path component.

Therefore opening `.` or `/` as an anchor no longer attempts to chmod the
caller's current directory or filesystem root.

Normal non-empty anchored directory creation and hardening behavior remains
unchanged.

## Failure behavior

Resource-limit violations fail closed using existing domain-specific error
types where applicable, including:

- `LifecycleStateStorageError`
- `AuthorityStateKeyStorageError`
- `IntelligenceUpdateVerificationError`
- `IntelligenceVerifiedCacheError`
- `IntelligenceSourceRegistryError`
- `SourceRegistryVerificationError`
- `SourceRegistryStateStorageError`
- `HTTPResponseTooLargeError`

The controls do not convert oversized input into trusted input and do not
silently truncate security-relevant files or authority state.

## Trust boundaries

Byte counts and collection counts are availability and resource-safety
controls. They do not create authenticity.

In particular:

- SHA-256 remains an integrity/equivalence property, not publisher identity.
- signed manifests are authentic only relative to the configured trust store.
- cache presence does not imply trust.
- stage verification does not mutate lifecycle acceptance state.
- activation remains the authority-state mutation boundary.
- local HMAC protection remains dependent on the independent local authority
  key and does not protect deletion/reset by itself.

## Deliberately retained reads

The bundled default intelligence policy is read from the installed
`php_sentinel` package resource. It is package-local trusted content rather
than an operator-supplied runtime authority file, so it remains outside the
operator-controlled local-file resource boundary introduced in this phase.

Verified-cache directory discovery necessarily iterates the configured cache
root, but now stops as soon as the configured visible-entry maximum is
exceeded.

## Non-goals

Phase 40 does not claim:

- OS-level memory quotas;
- CPU-time quotas;
- filesystem quota enforcement;
- protection from a malicious kernel;
- mount-namespace isolation;
- process sandboxing;
- protection from an attacker who controls both authority state and its local
  authentication key;
- automatic history pruning;
- automatic recovery from oversized or corrupted authority state.

Cross-platform filesystem semantics remain a separate Phase 41 concern.

## Phase 40 invariants

1. Security-sensitive remote bodies are bounded while streaming.
2. Security-sensitive local runtime files and operator-supplied comparison
   reports are bounded before full materialization.
3. Descriptor-bound readers preserve no-follow and regular-file checks where
   applicable.
4. Staged update size checks do not use pathname `stat()` followed by an
   unbounded pathname re-read.
5. Verified-cache artifacts are bounded during both inspection and
   pre-existing destination comparison.
6. Cache directory discovery fails once its configured cardinality ceiling is
   exceeded.
7. Collection cardinality is validated at model ingestion.
8. Mutable authority state is revalidated again at the persistence boundary.
9. Security history is never silently pruned to satisfy a resource limit.
10. Zero-component path anchors never chmod caller-owned `.` or `/`.
11. Resource limits are runtime safety constraints, not storage-format
    migrations.
12. Resource limits do not alter the project's evidence, trust, lifecycle, or
    authorization semantics.
