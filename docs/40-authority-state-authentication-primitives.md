# Phase 35 — Authority-State Authentication Primitives

Phase 35 introduces the cryptographic primitives required to make PHP Sentinel's
local rollback/history authority state tamper-evident.

This phase deliberately establishes the authenticated state format and
verification boundary only.

It does **not** yet make lifecycle or source-registry persistence authenticated
by default. Local key provisioning, storage, rotation, migration, and mandatory
storage integration are reserved for the next phase.

## Problem

Lifecycle and source-registry state currently protect rollback and signer
history using:

- hardened regular-file reads;
- no-follow semantics;
- race-resistant locking;
- device/inode identity checks;
- directory-descriptor anchoring;
- atomic state publication.

Those controls protect filesystem identity and transaction integrity.

They do not prove that a syntactically valid state file was produced by PHP
Sentinel using an authorized local state-authentication key.

A local actor able to replace a valid regular state file could therefore
construct structurally valid rollback/history state.

## Trust-domain separation

PHP Sentinel already uses Ed25519 for:

- intelligence manifests;
- source-registry manifests;
- signer delegation;
- delegation revocation.

Those are publisher/signing trust domains.

Phase 35 does not reuse those keys for local state authentication.

Local authority-state authentication is a separate trust domain.

This prevents a publisher key from implicitly becoming authority over PHP
Sentinel's local rollback/history persistence.

## Authentication primitive

Phase 35 uses:

`HMAC-SHA256`

with an explicit 32-byte local secret key.

The primitive provides integrity and origin authentication relative to the
configured local state-authentication key.

It does not provide confidentiality.

## Authenticated envelope

Authenticated authority state is represented by an
`AuthorityStateEnvelope`.

The envelope contains:

- `auth_version`;
- `context`;
- `algorithm`;
- `key_id`;
- `state`;
- `mac_b64`.

Version 1 currently supports:

- authentication version `1`;
- algorithm `hmac-sha256`;
- contexts `lifecycle` and `registry`.

The MAC must decode to exactly 32 bytes.

The key identifier follows the existing canonical identifier grammar:

`^[A-Za-z0-9][A-Za-z0-9._-]*$`

with a maximum length of 128 characters.

## Canonical signing payload

The HMAC input is deterministic canonical JSON containing:

- algorithm;
- authentication version;
- context;
- key identifier;
- normalized state payload.

JSON keys are sorted and compact separators are used.

The signing input is prefixed with the explicit domain:

`PHP-SENTINEL-AUTHORITY-STATE-HMAC-V1`

and additionally includes a context-specific domain:

- `LIFECYCLE`;
- `REGISTRY`.

This prevents the same authenticated state payload from being transferred
between lifecycle and registry authority domains.

## Verification semantics

Verification requires the caller to supply:

- the expected context;
- the expected key identifier;
- the exact 32-byte key.

Verification fails closed when:

- the context is wrong;
- the key identity is wrong;
- the key has the wrong size;
- the state payload changes;
- the MAC changes;
- the wrong key is supplied;
- the envelope uses malformed authentication metadata.

MAC comparison uses `hmac.compare_digest`.

State is returned for model validation only after authentication succeeds.

## Canonical envelope serialization

Phase 35 also provides deterministic envelope serialization for future durable
storage.

The serialized envelope uses:

- JSON;
- sorted keys;
- stable indentation;
- UTF-8;
- a trailing newline.

The canonical signing representation remains independent from presentation
indentation.

## Security invariants

Phase 35 establishes:

1. Local authority-state authentication has its own trust domain.
2. Publisher Ed25519 keys are not reused for local state authentication.
3. HMAC keys must be exactly 32 bytes.
4. Lifecycle and registry states are cryptographically domain-separated.
5. Context is authenticated.
6. Authentication version is authenticated.
7. Algorithm identifier is authenticated.
8. Key identifier is authenticated.
9. Entire normalized state payload is authenticated.
10. State modification invalidates the MAC.
11. MAC modification is rejected.
12. Wrong-key verification is rejected.
13. Wrong-context verification is rejected.
14. Wrong-key-identity verification is rejected.
15. MAC comparison uses constant-time comparison semantics provided by
    `hmac.compare_digest`.

## Important non-claims

Phase 35 does not yet claim that persisted lifecycle or source-registry state
is cryptographically protected during normal operation.

The current lifecycle and registry storage paths still use their existing
state models directly.

The new authenticated envelope is a cryptographic primitive and storage format
foundation.

Until key management and persistence integration are completed, existing state
files remain protected by the filesystem/storage hardening from Phases 32–34,
not by mandatory HMAC authentication.

## Next phase

Phase 36 should establish local authority-key management, including:

- key-file location and identity;
- secure key generation;
- no-follow key loading;
- exact regular-file validation;
- file mode enforcement;
- directory anchoring where appropriate;
- key rotation semantics;
- missing-key behavior;
- legacy unsigned-state migration policy;
- authenticated lifecycle-state persistence;
- authenticated source-registry-state persistence;
- fail-closed handling of invalid authenticated state.

Only after those boundaries are implemented should PHP Sentinel claim that its
persisted rollback/history authority state is cryptographically tamper-evident.

## Result

Phase 35 provides:

`state -> canonical domain-separated payload -> HMAC-SHA256 -> authenticated
authority-state envelope -> constant-time verification`

for both lifecycle and source-registry state contexts, while deliberately
keeping local state-authentication authority separate from publisher trust.
