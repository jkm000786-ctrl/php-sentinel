# Phase 14 — Trusted Policy Activation

Phase 14 connects Phase 13 trust verification to the normal unified
`php-sentinel scan` workflow.

## Default behavior

When no external intelligence arguments are supplied, PHP Sentinel uses
the bundled validated intelligence policy.

Its trust provenance is:

- state: `bundled_trusted`,
- signer: `php-sentinel-package`,
- algorithm: `package-bound`.

This remains package-local trust and is not represented as a PHP
upstream cryptographic signature.

## External activation contract

External intelligence requires all three arguments:

- `--policy`,
- `--manifest`,
- `--trust-store`.

Example:

`php-sentinel scan TARGET --policy policy.json --manifest manifest.json --trust-store trust.json`

Supplying only part of the trust bundle is rejected before target
validation or HTTP assessment begins.

## Activation pipeline

The activation path is:

1. load and schema-validate the policy,
2. load and validate the manifest,
3. load the operator trust store,
4. verify policy metadata,
5. verify canonical policy SHA-256,
6. resolve an enabled trusted signer,
7. verify the Ed25519 signature,
8. activate the policy only when the trust decision is trusted.

Any failure prevents the external policy from influencing assessment.

## Single-policy invariant

The same activated policy object is passed to the unified assessment
pipeline and therefore controls:

- CVE applicability decisions,
- fixed-version thresholds,
- remediation guidance,
- findings,
- canonical evidence identity,
- evidence provenance.

The corresponding trust decision is passed to provenance unchanged.

This prevents a policy from being verified and then silently replaced
before decision generation.

## Fail-closed ordering

Intelligence activation occurs before:

- local active validation,
- target HTTP collection,
- PHP fingerprinting,
- CVE decision generation.

An incomplete or untrusted external policy therefore cannot trigger
target interaction.

## Exit code

Trusted-policy activation failure uses CLI exit code `4`.

Existing exit semantics remain:

- HTTP/runtime failure: `2`,
- local validation/scope denial: `3`,
- intelligence activation denial: `4`.

## Evidence

New unified reports already contain Phase 13 trust provenance:

- `intelligence_policy_id`,
- `intelligence_sha256`,
- `intelligence_trust_state`,
- `intelligence_signer_id`,
- `intelligence_signature_algorithm`.

The interactive scan summary now also surfaces the selected policy,
trust state, and signer.
