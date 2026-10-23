# Phase 18 — Intelligence Update Channel Architecture

Phase 18 introduces a safe path for obtaining newer signed intelligence
without creating a second trust or activation authority.

## State machine

Remote content progresses through distinct states:

`remote -> untrusted staging -> locally verified cache -> activation`

These states are intentionally separate.

## Transport is not trust

A successful HTTPS request establishes only that bytes were retrieved.

It does not establish:

- publisher identity,
- policy integrity,
- signer trust,
- freshness,
- generation acceptance,
- rollback safety,
- activation authority.

The update channel therefore never marks content trusted merely because
it downloaded successfully.

## HTTPS-only staging

Remote policy and manifest URLs must use HTTPS.

Redirects are not followed.

Downloads are bounded by a maximum object size.

Policy and manifest bytes are fetched completely before either is
written to staging.

## Staging metadata

Staging records:

- source policy URL,
- source manifest URL,
- retrieval time,
- raw transport SHA-256 for each object,
- raw byte counts.

These hashes protect staging equivalence only. They do not authenticate
the publisher.

## Local trust anchor

The trust store is never downloaded by the update channel.

Verification requires an operator-supplied local trust-store path.

The staged policy and manifest then pass through the existing PHP
Sentinel Ed25519 manifest verification logic.

## Lifecycle verification

The candidate is checked against the existing lifecycle state:

- freshness,
- expiration,
- minimum generation,
- signer pinning,
- authorized signer rotation,
- rollback detection,
- replay detection.

Verification reads lifecycle state but deliberately does not advance it.

This keeps update discovery and activation separate.

## Verified candidate capability

Successful verification returns an in-process
`VerifiedUpdateCandidate`.

The constructor is module-sealed to reduce accidental trust-decision
laundering.

As with the Phase 16 activation capability, this is an architectural
boundary and not cryptographic protection against a hostile process
that can modify PHP Sentinel's runtime.

## Verified cache promotion

Promotion means moving verified bytes into an immutable local cache.

Promotion does not mean activation.

The staged transport hashes and parsed policy/manifest are rechecked
immediately before promotion to detect changes after verification.

The cache directory name includes:

- policy ID,
- generation,
- policy digest prefix.

An existing cache entry with different bytes is rejected.

## Activation remains authoritative

A cached update still must pass the existing verified activation
boundary before use.

The scan pipeline does not trust `verification.json` as authority.

Activation re-loads the policy, manifest, local trust store and
lifecycle state.

Only that existing activation path may record lifecycle acceptance.

## Failure semantics

If download, parsing, signature verification, lifecycle verification,
or promotion fails:

- existing bundled intelligence is unchanged,
- existing verified cache entries are unchanged,
- lifecycle acceptance state is not advanced,
- no scan policy is automatically replaced.

## Security interpretation

A verified intelligence update establishes policy authenticity relative
to the configured trust store and lifecycle rules.

It does not establish that a target is vulnerable.

It does not authorize active testing.

It does not add exploit execution behavior.
