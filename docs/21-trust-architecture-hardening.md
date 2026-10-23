# Phase 16 — Trust Architecture Hardening

Phase 16 strengthens PHP Sentinel's intelligence trust boundary.

## Controls introduced

### Manifest v3 domain separation

New manifests default to version 3.

The Ed25519 signature covers:

`PHP-SENTINEL-INTELLIGENCE-MANIFEST-V3\0 || canonical_manifest`

Manifest v1 and v2 remain verifiable for backward compatibility.

### Verified intelligence capability

Trusted external intelligence is carried as one
`VerifiedIntelligenceSelection` containing:

- policy,
- trust decision,
- lifecycle decision.

The constructor is module-sealed. Normal callers must obtain the
capability through the activation boundary.

### Trust laundering protection

Caller-created `IntelligenceTrustDecision(trusted=True)` values are not
accepted as verification authority.

Direct trust/lifecycle injection into the unified assessment pipeline
fails closed.

Custom policies remain usable for analysis, but without verified
activation they are explicitly unsigned/untrusted.

### Strict Ed25519 validation

PHP Sentinel requires:

- strict Base64 encoding,
- 32-byte Ed25519 public keys,
- 32-byte Ed25519 private keys,
- 64-byte Ed25519 signatures.

### Trust-store schema enforcement

Only explicitly supported trust-store versions are accepted.

Current supported version: `1`.

### Controlled signer rotation

A trusted successor signer may declare `authorized_predecessors`.

Rotation requires:

1. a valid successor signature,
2. explicit authorization of the previously pinned signer,
3. a strictly higher manifest generation.

Unapproved signer changes remain `signer_changed`.

### Human-readable provenance

Markdown reports expose:

- intelligence policy ID,
- intelligence SHA-256,
- trust state,
- signer ID,
- signature algorithm,
- lifecycle state,
- generation,
- issue time,
- expiration time.

`bundled_trusted` means PHP Sentinel package-local trust. It does not
claim independent authentication by the PHP upstream project.

## Interpretation boundary

Cryptographic trust proves neither vulnerability nor exploitation.

Lifecycle acceptance proves neither vulnerability nor exploitation.

Version applicability remains evidence of potential exposure only.
