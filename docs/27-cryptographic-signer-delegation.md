# Phase 22 — Cryptographic Signer Delegation & Key Rotation

Phase 22 replaces trust-store predecessor metadata as the authoritative
key-rotation mechanism.

## Root of trust

The local TrustStore remains the root trust anchor.

A signed delegation cannot introduce an arbitrary new key.

Both predecessor and successor signer keys must already exist as
enabled entries in the local TrustStore.

## Signed delegation object

A delegation binds:

- trust context (`intelligence` or `registry`),
- predecessor signer ID,
- successor signer ID,
- exact successor Ed25519 public key,
- delegation sequence,
- minimum successor generation,
- issued_at,
- expires_at,
- signature algorithm.

The predecessor signs the delegation with its own private key.

## Domain separation

Delegations use:

`PHP-SENTINEL-SIGNER-DELEGATION-V1`

The signed context field additionally prevents an intelligence signer
delegation from authorizing registry governance rotation, or vice
versa.

## Key binding

Signer ID alone is insufficient.

The signed delegation contains the exact successor public key.

Verification also requires that the local TrustStore's enabled successor
entry contains that exact public key.

This prevents signer-ID substitution.

## Rotation authorization

A signer change is accepted only when:

1. the new manifest signature verifies with an enabled successor key,
2. the predecessor key is still present and enabled locally,
3. a valid predecessor-signed delegation exists,
4. the delegation context matches,
5. the successor signer ID and public key match,
6. the delegation is currently valid,
7. manifest generation is greater than the previously accepted
   generation,
8. manifest generation meets the delegation's minimum successor
   generation.

## Legacy authorized_predecessors

`TrustedSigner.authorized_predecessors` remains parseable for
compatibility with existing trust-store files.

It is no longer accepted as authoritative rotation evidence.

Verification may report that the legacy field exists, but lifecycle
rotation authorization is populated only from validated signed
delegations.

## Delegation sequence

Delegations carry a monotonically meaningful sequence field.

Phase 22 selects the highest currently valid sequence for a direct
predecessor/successor pair.

Duplicate context/predecessor/successor/sequence tuples are rejected by
the TrustStore schema.

## Chain depth

Phase 22 deliberately supports direct one-hop delegation only:

`predecessor -> successor`

It does not recursively infer arbitrary delegation chains.

This bounds reasoning and prevents implicit transitive trust.

Multi-hop delegation requires a future design with explicit chain depth,
revocation, and historical delegation-state semantics.

## Expiry and replay resistance

Expired and future delegations do not authorize rotation.

A delegation also specifies the minimum successor policy/registry
generation it may authorize.

Existing policy and registry lifecycle rollback/replay protections remain
authoritative for accepted content generations.

## Independent trust contexts

The same delegation primitive is reused for:

- intelligence-policy signer rotation,
- source-registry signer rotation.

However, the signed `context` value makes their authorities distinct.

A valid intelligence delegation is invalid for registry rotation.

## Security interpretation

A signed delegation proves that a locally trusted predecessor key
authorized a specific locally trusted successor key for a specific PHP
Sentinel trust context.

It does not:

- add the successor to the root trust store,
- authorize an untrusted manifest,
- bypass lifecycle rollback protection,
- authorize target testing,
- authorize exploitation.
