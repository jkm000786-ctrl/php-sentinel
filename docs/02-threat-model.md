# Threat Model

## Purpose

PHP Sentinel is an evidence-driven PHP exposure and vulnerability assessment
platform.

Its security model is designed to prevent weak evidence, untrusted intelligence,
unsafe transport, stale authority, local filesystem manipulation, and
authorization mistakes from being converted into authoritative vulnerability
claims or trusted update state.

The central security principle is:

> Evidence, transport, signatures, lifecycle state, source authorization, and
> runtime testing authorization are separate trust boundaries.

A successful check at one boundary never substitutes for another.

## Protected assets

PHP Sentinel protects the integrity of:

- vulnerability-intelligence policy;
- signed intelligence manifests;
- signed source registries;
- signer and delegation trust decisions;
- revocation history;
- lifecycle and rollback state;
- verified-cache identity and provenance;
- local authority-state authentication keys;
- authorized target scope;
- evidence provenance;
- operational security-audit records as descriptive observability.

The operational audit stream is not an authority asset and is never consulted
for trust or authorization decisions.

## Security objectives

The v1 security objectives are:

1. Never treat a PHP version banner as proof of vulnerability.
2. Distinguish upstream version applicability from vendor backport status.
3. Keep facts, hypotheses, exposure assessments, and validated findings
   separate.
4. Permit active validation only within explicit authorization boundaries.
5. Refuse active validation against non-loopback/public destinations where the
   local validation design requires loopback containment.
6. Authenticate intelligence independently from transport success.
7. Authenticate source-registry policy independently from intelligence
   manifests.
8. Prevent rollback, replay, signer-rotation abuse, and revoked delegation from
   silently replacing newer authority state.
9. Bind cached activation to the exact verified cache identity selected under
   current source policy.
10. Prevent symbolic-link and pathname races from redirecting
    security-sensitive file access where supported platform capabilities exist.
11. Authenticate persisted authority state with a local HMAC key.
12. Fail closed when mandatory filesystem-security capabilities are unavailable.
13. Bound remote and local security-sensitive inputs to reduce resource-exhaustion
    risk.
14. Keep operational audit logging descriptive and non-authoritative.

## Adversaries and failure sources

The threat model considers:

- malicious or compromised update infrastructure;
- DNS rebinding or hostile name resolution;
- unexpected HTTP redirects;
- a connected peer different from the prevalidated DNS destination;
- malicious or compromised intelligence signers;
- globally trusted signers that are not authorized for a specific source;
- malicious or compromised source-registry signers;
- revoked or stale delegation authority;
- rollback or replay of previously valid signed material;
- local attackers able to modify writable cache or state paths;
- symbolic-link substitution and pathname race conditions;
- cache replacement between selection and authoritative activation;
- corruption or deletion of lifecycle/revocation state;
- malformed or oversized remote/local inputs;
- unsupported platform security semantics;
- operator error;
- stale, incomplete, or misleading evidence;
- audit-log alteration by an actor with sufficient local write access.

## Intelligence supply-chain boundaries

### Transport

Remote intelligence and registry transport requires:

- HTTPS;
- no redirects;
- proxy-environment isolation through `trust_env=False`;
- hostname resolution before connection;
- globally routable public destination addresses;
- connected-peer verification against the prevalidated DNS result;
- bounded streamed response bodies.

Transport success does not establish intelligence authenticity.

### Source registry

The signed source registry controls which:

- sources;
- channels;
- URLs;
- minimum generations;
- signer identities

are authorized for a registry-selected intelligence workflow.

Registry trust does not create intelligence trust.

A signer may be globally trusted while still being unauthorized for the selected
source/channel.

### Intelligence signatures

Signed intelligence manifests are verified against the current trust store.

A valid cryptographic signature is necessary but is not sufficient for
activation.

Lifecycle, source policy, revocation, freshness, generation, and rollback checks
remain independent.

## Delegation, rotation, and revocation

Delegation is intentionally constrained.

The current model uses one-hop delegation and persistent revocation history.

Valid revocation evidence is recorded only at authoritative activation
boundaries.

Security rules include:

- lower revocation sequences are rejected;
- same-sequence different-digest revocations fail closed;
- persisted revocation history remains effective;
- intelligence and registry revocation histories remain context-separated;
- revoked rotation authority cannot activate new trusted state.

## Lifecycle and rollback authority

Authoritative lifecycle state prevents older accepted generations from silently
replacing newer state.

Lifecycle history is re-evaluated at activation.

Verification and cache discovery are read-only with respect to lifecycle
authority.

An accepted lifecycle mutation occurs only at the authoritative activation
boundary.

## Verified-cache threat model

Verified cache content is not permanent trust authority.

Cache discovery proves structure, identity, provenance, and internal
consistency.

Authoritative activation re-evaluates current:

- trust;
- source policy;
- signer authorization;
- lifecycle;
- revocation;
- freshness;
- rollback rules.

Required cache artifacts are opened through hardened descriptor-relative
boundaries on supported platforms.

Cached registry activation is additionally bound to the exact
`IntelligenceVerifiedCacheEntry` that passed source-policy authorization.

If the cache entry changes between selection and authoritative activation,
activation fails before lifecycle authority state is advanced.

## Local authority state

Lifecycle and registry authority state is authenticated using a local HMAC key.

The authenticated envelope detects:

- payload tampering;
- wrong-key use;
- authentication-context mismatch;
- unsigned existing state where authenticated state is required.

The local HMAC design does not protect against deletion of both the authority
state and its key.

Missing, corrupt, unauthenticated, and unsupported states are distinguished and
fail closed according to the recovery model.

Automatic history reset is not permitted.

## Filesystem threat model

Security-sensitive local storage uses descriptor-oriented controls where the
platform provides the required semantics.

Controls include:

- anchored parent-directory traversal;
- `O_NOFOLLOW`;
- `O_DIRECTORY` where required;
- descriptor-relative opens;
- regular-file validation;
- same-directory atomic publication;
- exclusive temporary-file creation;
- file `fsync`;
- bounded reads.

Mandatory security capabilities are checked explicitly.

Missing capabilities do not silently degrade into weaker pathname behavior.

## Cross-platform boundary

Linux/WSL/POSIX-style environments provide the strongest currently implemented
filesystem-security semantics.

PHP Sentinel does not claim native Windows ACL or reparse-point protection
equivalent to the POSIX descriptor model.

If the runtime cannot provide a mandatory no-follow or descriptor-security
capability, the relevant operation fails closed.

Cross-platform support means explicit capability evaluation, not silent
security downgrade.

## Resource-exhaustion boundary

Security-sensitive inputs are bounded.

Limits exist for:

- remote HTTP bodies;
- local policy and manifest files;
- staged artifacts;
- verified-cache artifacts;
- authority state;
- authority keys;
- registry data;
- audit events and audit files;
- verified-cache entry counts;
- security-history collection cardinality.

Resource limits are runtime-safety controls.

They do not change trust, evidence, lifecycle, or authorization semantics.

## Active validation and testing authorization

Public or third-party targets are not automatically authorized merely because
they are reachable.

PHP Sentinel separates:

- passive evidence collection;
- exposure hypotheses;
- local/controlled validation;
- authoritative findings.

Active validation requires explicit authorization.

Where the validation implementation is intentionally loopback-contained, public
destinations are rejected rather than probed.

The project does not provide a generic public exploit or RCE launcher.

## Evidence model

Evidence strength is independent from vulnerability severity.

A version range may support:

`potentially_affected`

or:

`potential_exposure`

but does not by itself establish:

`confirmed vulnerable`.

Vendor backports, build provenance, SAPI/configuration, runtime behavior, and
direct validation evidence may materially change the assessment.

## Operational audit boundary

Operational security-audit events are descriptive only.

The audit stream:

- records completed security-relevant operations;
- is bounded;
- uses hardened local file access;
- contains structured fields rather than arbitrary free-form detail;
- is not consulted for trust, authorization, rollback, source selection, or
  activation.

The current JSONL audit stream is not tamper-evident.

Deletion or modification of the audit log must never reset or grant authority.

## Residual risks and explicit non-claims

PHP Sentinel v1 does not claim protection against:

- a fully privileged hostile kernel or administrator;
- mount-namespace manipulation by a sufficiently privileged local attacker;
- deletion/reset of both authenticated authority state and its local HMAC key;
- compromise of all currently trusted signing authority;
- compromise of the operator's host before PHP Sentinel executes;
- secure time synchronization;
- cryptographically tamper-evident operational audit history;
- remote immutable logging;
- non-repudiation;
- Windows ACL/reparse-point hardening equivalent to the POSIX implementation;
- reconstruction of lost rollback/revocation history;
- safe automatic restoration from arbitrary old backups;
- unlimited denial-of-service resistance;
- proof of vulnerability from version information alone.

## v1 threat-model closure

The initial Phase 1 threat model focused primarily on false positives,
unauthorized active testing, scanner load, and evidence provenance.

The v1 system now includes a substantially broader trusted-intelligence and
authority architecture.

The authoritative security model therefore includes:

`transport -> registry authorization -> intelligence signature -> current trust
-> revocation/delegation -> lifecycle/rollback -> verified cache identity ->
authoritative activation`

with evidence and operational audit remaining separate from authority.

Any future feature that bypasses one of these boundaries must be treated as a
security-design change rather than a convenience refactor.
