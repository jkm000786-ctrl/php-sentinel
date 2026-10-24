# Phase 43 — Operational Security Audit Logging

## Objective

Phase 43 adds a bounded, structured operational security-audit channel for
PHP Sentinel's trusted-intelligence workflow.

The audit stream records descriptive events for security-relevant operations
without becoming part of any trust, authorization, rollback, registry,
revocation, cache-selection, or activation decision.

The central rule is:

> The operational audit log is never an authority input.

## Scope

Phase 43 currently records successful events for:

- remote intelligence staging;
- staged intelligence verification;
- verified-cache promotion;
- authoritative intelligence activation;
- authoritative signed source-registry activation.

The operator-facing update CLI exposes an optional:

`--audit-log PATH`

for the relevant update, source-registry, and activation commands.

If the option is omitted, existing behavior is unchanged.

## Structured event schema

Each audit event is a versioned structured object.

The schema contains bounded fields such as:

- event timestamp;
- event type;
- outcome;
- component;
- operation;
- policy ID;
- registry ID;
- signer ID;
- source ID;
- channel;
- generation;
- trust state;
- lifecycle state;
- policy SHA-256;
- manifest SHA-256;
- reason code.

Unknown fields are rejected.

The schema intentionally does not provide a generic free-form `detail` field.

This reduces the chance that callers accidentally place secret-bearing or
unbounded operator text into the audit stream.

## Secret-handling boundary

Audit events must not contain:

- private signing keys;
- authority-state HMAC keys;
- authentication headers;
- cookies;
- session tokens;
- API tokens;
- passwords;
- complete fetched response bodies;
- complete trust stores;
- complete signed manifests merely for convenience.

Identifiers, bounded state labels, generations, and cryptographic digests are
preferred over raw security-sensitive material.

A digest is an integrity or identity reference. It is not, by itself,
authenticity proof.

## JSONL storage

The audit stream is stored as newline-delimited JSON (`JSONL`).

Each event is serialized deterministically with:

- sorted keys;
- compact separators;
- UTF-8 encoding;
- one event per line.

The current limits are:

- maximum event size: 16 KiB;
- maximum audit-log size: 8 MiB.

These limits are resource-safety controls. They are not retention or archival
policy.

## Filesystem security

Audit storage uses the same explicit filesystem-security posture established by
the authority hardening phases.

Parent directories are opened through descriptor-anchored traversal.

The implementation:

- rejects `..` traversal;
- refuses symbolic-link directory components;
- optionally creates missing directories one component at a time relative to
  an already-open parent descriptor;
- opens the audit basename relative to the anchored parent;
- uses `O_NOFOLLOW`;
- validates the opened object as a regular file;
- applies owner-only mode where the platform supports POSIX mode enforcement;
- requires successful file `fsync`;
- treats directory `fsync` as best-effort.

Platforms that cannot provide the required no-follow or anchored-directory
semantics fail closed for direct audit storage access.

## Non-authoritative failure semantics

Operational logging is deliberately separated from authoritative mutation.

For authoritative activation:

1. trust is evaluated;
2. lifecycle and revocation rules are evaluated;
3. authoritative state is committed;
4. the accepted result is constructed;
5. the audit event is attempted.

If the post-commit audit append fails, that failure does not convert an already
accepted authority mutation into a rejected activation.

The same principle applies to successful staging, verification, and cache
promotion.

Audit-storage failure therefore does not:

- revoke trust;
- change lifecycle state;
- change authorization;
- roll back an accepted generation;
- change source-registry authority;
- invalidate an otherwise successful cache promotion.

This avoids an ambiguous state where the API reports security failure even
though authoritative state has already committed.

## Read semantics

Audit-log reads are descriptive only.

Missing audit files or missing parent directories are interpreted as an empty
audit stream.

Malformed, oversized, unsafe, symbolic-link, or unsupported audit storage is
reported as an audit-storage error.

No audit-log content is consulted during:

- manifest verification;
- signer authorization;
- delegation validation;
- revocation processing;
- rollback protection;
- source selection;
- verified-cache selection;
- lifecycle evaluation;
- registry activation;
- intelligence activation.

Deletion, truncation, or corruption of the audit file must therefore never
create a trust bypass or authority reset.

## Trust separation

The audit channel is not:

- signed intelligence;
- signed registry state;
- authenticated authority state;
- rollback state;
- revocation history;
- cryptographic authorization evidence;
- signed evidence;
- a policy input.

Its presence cannot grant authority.

Its absence cannot remove authority.

Its contents cannot override current trust or lifecycle evaluation.

## Tamper-evidence non-claim

The Phase 43 JSONL audit stream is not tamper-evident.

It is not currently protected by:

- an HMAC chain;
- a signature chain;
- append-only filesystem enforcement;
- remote immutable storage;
- a transparency log;
- an external monotonic counter.

An operator or attacker with sufficient local write access may be able to alter
or delete the audit file.

Phase 43 therefore provides operational observability, not a cryptographic
forensic ledger.

If a future phase requires tamper-evident audit history, that must use a
separate trust design and must still remain isolated from runtime authorization
and activation authority.

## Event ordering

Events represent completed operations.

For example:

- `update_staged` is emitted only after staged artifacts and metadata have been
  written; registry-selected staging emits the event only after `source_id` and
  `channel` provenance have been attached to the stage metadata;
- `update_verified` is emitted only after trust and lifecycle checks produce a
  valid read-only candidate; registry-selected verification additionally
  requires the manifest signer to pass the selected source/channel signer
  authorization before the success event is emitted;
- `update_promoted` is emitted after successful cache promotion, including an
  idempotent identical-cache result;
- activation-accepted events are emitted only after their authoritative
  acceptance boundary succeeds.

The log therefore describes observed successful transitions rather than
predicting them.

## CLI boundary

The update CLI exposes the audit path explicitly.

There is no hidden default global audit file.

This keeps deployment policy with the operator and prevents PHP Sentinel from
silently selecting an authority-adjacent storage location.

CLI plumbing forwards the path into the existing lower-level security
boundaries. The CLI does not duplicate trust or audit-decision logic.

## Security invariants

Phase 43 establishes:

1. Audit data is descriptive only and never an authority input.
2. Existing behavior is unchanged when no audit path is configured.
3. Audit event schemas reject unknown fields.
4. No generic free-form detail field exists.
5. Event and file sizes are bounded.
6. Audit files use owner-only mode where supported.
7. Audit basenames are opened with no-follow semantics.
8. Audit parent paths use descriptor-anchored traversal.
9. Symbolic-link ancestors are rejected.
10. Missing audit storage does not affect trust or activation.
11. Audit-write failure does not reverse or mask an already successful
    authoritative commit.
12. Staging, verification, and promotion remain non-authoritative operations.
13. Registry trust and intelligence trust remain independent.
14. Audit deletion or corruption cannot reset rollback or revocation history.
15. The audit stream is not claimed to be tamper-evident.

## Non-claims

Phase 43 does not provide:

- cryptographically tamper-evident logging;
- remote log shipping;
- SIEM integration;
- log rotation;
- retention policy;
- cross-host correlation;
- secure time synchronization;
- non-repudiation;
- append-only operating-system enforcement;
- signed audit events;
- automatic incident response;
- authorization derived from logs.

Those are separate operational or trust-system concerns.

## Result

PHP Sentinel now exposes a structured operational record of the trusted-update
and activation workflow while maintaining strict separation between
observability and authority.

The resulting model is:

`operation -> authoritative or non-authoritative result -> descriptive audit`

and never:

`audit -> trust or authorization decision`

This preserves the project's core evidence and authority discipline while adding
operator-visible security logging for Phase 43.
