# Phase 13 — Trusted Intelligence Manifests

Phase 13 separates content integrity from signer authenticity.

Phase 12 established reproducible policy SHA-256 identity. A digest
proves which content was used but does not establish who authorized it.

Phase 13 adds detached Ed25519 manifests and an explicit trust store.

## Detached manifest

A signed manifest contains:

- manifest version,
- policy ID,
- policy schema version,
- canonical policy SHA-256,
- issuance time,
- signer ID,
- signature algorithm,
- Ed25519 signature.

The signature covers canonical manifest metadata. The vulnerability
policy itself remains unchanged.

## Trust store

A trust store contains explicitly enabled signer identities and their
Ed25519 public keys.

A signer is not trusted merely because a public key is supplied next to
a policy. Trust must already exist in the operator-controlled trust
store.

## Verification states

PHP Sentinel distinguishes:

- `bundled_trusted`,
- `trusted`,
- `unsigned`,
- `unknown_signer`,
- `invalid_signature`,
- `digest_mismatch`,
- `metadata_mismatch`,
- `unsupported_algorithm`.

A valid signature from an unknown signer is not trusted.

## Fail-closed external activation

`load_verified_external_policy()` returns an external policy only after:

1. policy schema validation,
2. supported policy-schema validation,
3. manifest validation,
4. policy SHA-256 match,
5. signer lookup in the trust store,
6. Ed25519 signature verification.

Any failed trust condition prevents activation.

## CLI verification

Use:

`php-sentinel-intel --policy policy.json --verify-manifest manifest.json --trust-store trust.json`

Exit behavior:

- verified trusted policy: exit 0,
- malformed policy/manifest/trust store: exit 2,
- untrusted or invalid signature: exit 3.

## Provenance

Assessment provenance now records:

- `intelligence_trust_state`,
- `intelligence_signer_id`,
- `intelligence_signature_algorithm`.

The bundled PHP Sentinel policy is recorded as:

`bundled_trusted`

with local package identity:

`php-sentinel-package`

This means trusted as bundled application content. It does not claim
that PHP upstream cryptographically signed PHP Sentinel's bundled
policy.

## Comparison semantics

If intelligence content changes:

`policy_changed`

If the intelligence digest remains identical but signer/trust
provenance changes:

`trust_changed`

Cross-target incompatibility remains the strongest comparison guard
unless the operator explicitly allows cross-target comparison.

## Private-key boundary

PHP Sentinel does not bundle or persist publisher private keys.

`create_signed_manifest()` accepts private-key material only from the
calling publisher process.

Private-key custody belongs outside the assessment engine.
