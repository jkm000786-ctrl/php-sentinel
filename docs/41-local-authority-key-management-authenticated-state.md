# Local Authority Key Management and Authenticated State Persistence

## Scope

Phase 36 makes PHP Sentinel lifecycle authority state cryptographically
authenticated with the Phase 35 domain-separated HMAC-SHA256 envelope.

The local authority-state trust domain remains separate from publisher
Ed25519 intelligence and registry trust.

## Local key

The default local key file is:

`~/.local/state/php-sentinel/authority-state.key.json`

For an explicitly supplied authority-state path, authoritative activation uses
the sibling file:

`authority-state.key.json`

The version-1 key record contains:

- `key_file_version`
- `key_id`
- `algorithm`
- strict-base64 32-byte key material

Key creation uses exclusive creation, `O_NOFOLLOW` where available, regular-file
validation, durability sync, and owner-only mode enforcement where supported.

The key is not encryption material. It authenticates state integrity and local
origin only.

## Authoritative activation

External intelligence activation and signed source-registry activation are the
authoritative mutation boundaries.

When lifecycle state is enabled, these boundaries:

1. load or exclusively create the local authority key;
2. require lifecycle/registry state to be authenticated;
3. verify the envelope context and key identity;
4. reject MAC tampering, wrong keys, wrong contexts, or unsigned existing state;
5. persist subsequent lifecycle mutations as authenticated envelopes.

Read-only source-registry verification does not create a state file or key.

## Legacy state migration

Unsigned legacy state is not silently upgraded during activation.

Operators must explicitly migrate it with:

- `migrate_lifecycle_state_to_authenticated(...)`
- `migrate_source_registry_state_to_authenticated(...)`

Migration runs under the existing descriptor-anchored lifecycle lock and writes
the authenticated envelope through the existing hardened temporary-file and
rename transaction.

Missing, malformed, or already-authenticated state is rejected rather than
silently rewritten.

## Key rotation policy

Version 1 intentionally does not perform transparent in-place key rotation.

The key identifier is cryptographically bound into every authority-state MAC.
Replacing the local key therefore causes existing state to fail closed.

This is deliberate: replacing the key independently of lifecycle and registry
state could orphan rollback/revocation history or create a crash window where
some authority files are signed by one key and others by another.

A future multi-key/keyring or transactional rotation design may add coordinated
rotation. Until then:

- existing key files are created exclusively and are not overwritten;
- changing key identity is not accepted as implicit rotation;
- state authenticated under another key must not be treated as legacy state;
- operators must preserve the local authority key with the authority-state
  files it authenticates.

## Security properties

Phase 36 provides tamper evidence and local authenticity relative to the
independently protected 32-byte local secret.

It does not provide confidentiality.

It does not defend against an attacker who can modify both the authority-state
files and the local key.

Ancestor/root path anchoring and broader cross-platform filesystem semantics
remain later hardening work.
