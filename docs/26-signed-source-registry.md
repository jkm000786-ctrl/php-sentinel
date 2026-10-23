# Phase 21 — Signed Source Registry & Registry Rollback Protection

Phase 21 authenticates the source registry itself.

The Phase 20 unsigned registry remains available for explicit
operator-local configuration, but it must not be interpreted as a
publisher-authenticated registry.

## Separate trust domains

PHP Sentinel now has two independent signature domains:

1. intelligence-policy manifests,
2. source-registry manifests.

Registry signatures use:

`PHP-SENTINEL-SOURCE-REGISTRY-MANIFEST-V1`

This prevents an intelligence-policy signature from being reused as a
registry signature or vice versa.

## Registry digest

The registry is serialized canonically with deterministic JSON ordering
and compact separators.

Its SHA-256 is embedded in the signed registry manifest.

The digest establishes content integrity/equivalence. Publisher
authenticity comes from the Ed25519 signature and the dedicated local
registry trust store.

## Dedicated registry trust store

Signed registry verification accepts a registry trust-store path
separately from the intelligence-policy trust-store path.

The same TrustStore schema is reused, but the two files represent
different authorities and are supplied through different API/CLI
parameters.

Configuring a key for registry trust does not create intelligence-policy
trust.

## Registry lifecycle

Registry manifests include:

- generation,
- issued_at,
- expires_at,
- signer ID.

Lifecycle evaluation rejects:

- future-issued manifests,
- expired manifests,
- stale manifests,
- generations below the operator minimum,
- rollback to lower generations,
- same-generation/different-digest replay,
- unauthorized signer changes.

## Registry signer rotation

A new registry signer can succeed only when:

- it is trusted by the dedicated registry trust store,
- its trust-store entry explicitly names the previously pinned signer
  as an authorized predecessor,
- the new registry generation is greater than the accepted generation.

## Separate rollback state

Registry rollback state is stored independently from intelligence-policy
lifecycle state.

Default conceptual paths are:

- intelligence:
  `intelligence-lifecycle.json`
- registry:
  `source-registry-lifecycle.json`

Registry state therefore cannot overwrite or masquerade as policy
lifecycle state.

## Hardened persistence

Registry lifecycle state follows the Phase 17 persistence discipline:

- dedicated state file,
- exclusive lock,
- bounded lock acquisition,
- 0700 directory mode where supported,
- 0600 state/lock files where supported,
- fsync before replace,
- atomic same-directory replacement,
- directory fsync where supported,
- evaluation-to-commit snapshot comparison.

As with intelligence lifecycle persistence, this protects durability and
race behavior but is not cryptographically tamper-evident against a
hostile local administrator.

## Verify versus activate

`registry-verify` authenticates and evaluates a registry without
advancing rollback state.

`registry-activate` performs the same checks and records the accepted
generation.

This mirrors the update-channel distinction between inspection and
state-changing acceptance.

## Signed-registry intelligence activation

PHP Sentinel includes an integration boundary that:

1. verifies and activates the signed registry,
2. resolves the requested source/channel from that verified registry,
3. selects only cache entries carrying matching source/channel
   provenance,
4. checks the registry-authorized intelligence signer,
5. delegates actual intelligence activation to the existing
   `activate_cached_intelligence()` boundary.

Therefore registry authenticity never replaces intelligence-policy
signature or lifecycle verification.

Both authorities must succeed.

## Security interpretation

A trusted registry proves that the registry policy was signed by a key
trusted for registry governance.

It does not prove:

- an intelligence bundle is trusted,
- a target is vulnerable,
- active target testing is authorized,
- exploit execution is authorized.
