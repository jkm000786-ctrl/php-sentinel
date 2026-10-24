# Phase 44 — v1 Security Review and Threat-Model Closure

## Objective

Phase 44 performs a system-level security review of PHP Sentinel v1 after the
trusted-intelligence, authority-state, cache, transport, platform, resource, and
operational-audit hardening phases.

The goals are:

1. verify that the implemented security boundaries remain compositionally
   consistent;
2. identify stale assumptions or gaps that only appear across subsystem
   boundaries;
3. close confirmed defects with regression coverage;
4. update the project threat model to describe the actual v1 architecture;
5. document residual risks and explicit non-claims.

## Review scope

The review covered:

- intelligence signatures and current trust;
- source-registry authorization;
- source/channel signer restrictions;
- delegation and revocation;
- lifecycle and rollback protection;
- registry lifecycle state;
- trusted update transport;
- DNS and connected-peer containment;
- staged-update provenance;
- verified-cache discovery and activation;
- cache filesystem identity;
- descriptor-relative storage semantics;
- authenticated authority state;
- authority-key handling;
- recovery and format governance;
- resource/DoS limits;
- cross-platform capability semantics;
- operational security-audit logging;
- end-to-end supply-chain adversarial tests.

## Confirmed finding 1 — registry staging audit provenance

### Problem

The generic remote-staging layer emitted `update_staged` before the
source-registry wrapper attached:

- `source_id`;
- `channel`.

The resulting event described a successful operation but lost the registry
provenance that selected the update source.

### Security impact

This did not weaken trust or authorization.

The defect was an observability and forensic-context error.

### Closure

Registry-selected staging now suppresses the generic stage event, attaches
source/channel provenance, persists the enriched stage metadata, and then emits
the source-aware success event.

A regression test verifies that the event retains both identifiers.

## Confirmed finding 2 — verification audit success before source signer authorization

### Problem

The generic staged-verification layer emitted `update_verified` after global
trust/lifecycle validation but before the source-registry wrapper enforced the
selected source's `allowed_signer_ids`.

A globally trusted signer that was unauthorized for the selected source could
therefore produce a success audit event immediately before the wrapper rejected
the candidate.

### Security impact

No unauthorized candidate reached authoritative activation.

The defect was an audit-ordering error: the event could incorrectly describe a
registry-selected verification as successful before all source-specific
authorization checks were complete.

### Closure

Registry-selected verification now suppresses the generic verification event.

The wrapper:

1. verifies the staged candidate;
2. enforces current source/channel signer authorization;
3. only then emits the source-aware `update_verified` event.

Regression coverage verifies both rejection-without-success-event and the
authorized success case.

## Confirmed finding 3 — cache selection/activation identity TOCTOU

### Problem

Registry cached activation originally:

1. selected and inspected a verified-cache entry;
2. checked current source URLs and authorized signer;
3. invoked generic cached activation;
4. generic cached activation reopened and re-inspected the cache;
5. the registry wrapper performed another signer check only after activation.

The two cache inspections were individually hardened, but they were not bound
to the same `IntelligenceVerifiedCacheEntry`.

A local cache mutation between the registry authorization inspection and the
activation inspection could therefore make the second inspection operate on a
different valid cache identity.

The post-activation signer check was too late to be the primary source-policy
boundary because lifecycle authority mutation may already have succeeded.

### Closure

`activate_cached_intelligence()` now accepts an optional
`expected_entry`.

After its hardened reinspection it compares the actual cache entry against the
registry-authorized entry.

If they differ, activation fails before
`activate_verified_intelligence_objects()` and therefore before authoritative
lifecycle state mutation.

The registry wrapper passes its selected entry as `expected_entry`.

The redundant post-activation signer check was removed.

Regression coverage verifies that a changed cache identity is rejected and that
no lifecycle state is committed.

## Security boundaries verified

### Transport

The review confirmed:

- HTTPS-only update URLs;
- redirects refused;
- environment proxy inheritance disabled;
- preconnection DNS validation;
- globally routable public-address requirement;
- connected-peer containment against the resolved set;
- bounded streamed bodies.

Transport remains independent from cryptographic trust.

### Registry and intelligence trust separation

The signed source registry may narrow:

- source;
- channel;
- URLs;
- minimum generation;
- signer IDs.

It does not create intelligence cryptographic trust.

Intelligence manifests must still pass current trust, lifecycle, revocation,
freshness, and rollback checks.

### Delegation and revocation

Persistent revocation history remains fail closed.

The system rejects:

- lower revocation sequences;
- same-sequence different-digest replacements;
- revoked rotation authority.

Verification remains read-only.

Revocation history is persisted only at authoritative activation boundaries.

### Lifecycle authority

Lifecycle state remains the authoritative rollback/freshness history.

Staging, verification, cache discovery, and promotion do not advance lifecycle
authority.

### Cache

Verified-cache metadata remains descriptive rather than trust authority.

Cache discovery and activation verify structure, artifact identity, metadata
consistency, provenance, and bounded contents.

Authoritative activation re-evaluates current trust and lifecycle state.

Registry-selected activation is now also bound to the exact source-authorized
cache identity.

### Local state

Lifecycle and registry authority state remains authenticated with a local HMAC
key.

Authenticated state detects payload/context/key mismatch and fails closed.

Recovery does not automatically reset corrupted or missing history.

### Filesystem

Security-sensitive operations retain:

- anchored traversal;
- mandatory no-follow behavior;
- descriptor-relative access;
- regular-file checks;
- exclusive temporary files;
- atomic same-directory publication;
- file synchronization;
- bounded reads.

Missing mandatory platform capabilities fail closed.

### Resource limits

The review confirmed bounded:

- HTTP bodies;
- staged artifacts;
- verified-cache artifacts;
- local authority files;
- cache entry counts;
- security-history cardinality;
- operational audit events/log size.

The implementation does not silently prune security history to satisfy limits.

### Operational audit

Audit logging remains descriptive only.

Phase 44 additionally confirms that registry-selected stage/verify success
events are emitted only after registry-specific provenance and authorization are
complete.

Audit-write failure does not change authority decisions.

The JSONL audit stream remains explicitly non-tamper-evident.

## End-to-end adversarial coverage

Existing supply-chain tests cover composed scenarios including:

- valid signed supply-chain activation;
- raw registry tampering after cache promotion;
- legitimately re-signed registry URL changes;
- legitimately re-signed signer restrictions;
- current trust removal/revocation;
- cache artifact tampering;
- registry rollback;
- intelligence lifecycle rollback/tamper;
- cache provenance metadata tampering.

Phase 44 adds focused coverage for:

- source-aware stage audit provenance;
- no verification-success event before source signer authorization;
- source-aware verification success after full authorization;
- cache identity change between selection and activation.

## Residual risks

The following remain accepted v1 residual risks or explicit non-claims.

### Privileged local attacker

The filesystem model reduces pathname and symbolic-link attacks but does not
claim protection from a fully privileged kernel/administrator capable of
mount-namespace or equivalent system-level manipulation.

### Authority-state deletion/reset

The local HMAC model detects modification but does not by itself prevent an
attacker able to delete both:

- authority state;
- the corresponding local authentication key.

Operational deployment must protect those files and backups appropriately.

### Audit tampering

The operational audit log is not cryptographically tamper-evident.

It provides observability, not non-repudiation or an immutable forensic ledger.

### Native Windows equivalence

PHP Sentinel does not claim native Windows ACL/reparse-point security equivalent
to its strongest POSIX/Linux/WSL descriptor model.

Mandatory operations fail closed when required capabilities are unavailable.

### Trusted signer compromise

If an attacker compromises currently trusted signing authority and remains
within all currently valid registry/delegation/lifecycle constraints, signature
verification alone cannot identify that compromise.

Key revocation, trust-store governance, and operational response remain
necessary.

### Time authority

Freshness and expiry depend on the supplied/system clock.

v1 does not provide secure external time synchronization or a trusted monotonic
time authority.

### Availability

Resource limits reduce several denial-of-service classes but do not claim
general DoS immunity.

### Backup restoration

A cryptographically valid old backup is not automatically safe to restore.

v1 does not reconstruct lost rollback/revocation history or automatically select
a trusted backup.

## Threat-model update

The original Phase 1 threat model described only:

- false positives from banners;
- ignored distro/LTS backports;
- unauthorized active testing;
- scanner load;
- evidence provenance.

That model is no longer sufficient for v1.

`docs/02-threat-model.md` is updated in Phase 44 to describe the complete
trusted-intelligence and authority architecture.

## v1 security posture

The review supports the following v1 security posture:

- evidence does not become truth merely because it is machine-observed;
- transport does not become trust merely because TLS succeeds;
- registry authorization does not become intelligence signature trust;
- cached verification does not become permanent authority;
- cryptographic trust does not bypass lifecycle/revocation state;
- audit history does not become authorization input;
- unsupported platform semantics do not silently downgrade security;
- authoritative mutation occurs only after the complete current decision chain
  succeeds.

The resulting authority path is:

`transport -> registry authorization -> intelligence trust -> delegation /
revocation -> lifecycle / rollback -> cache identity -> authoritative
activation`

Phase 44 closes the reviewed v1 threat-model gaps without broadening PHP
Sentinel into an unrestricted exploitation platform.

## Verification status

Before the Phase 44 documentation closure, the hardening changes passed:

- Ruff full source/test lint;
- 369 targeted security regression tests;
- 557 full repository tests;
- `git diff --check`.

The final documentation commit should preserve the same full gate.
