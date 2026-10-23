# Phase 12 — Policy Provenance, Integrity, and Safe Validation

PHP Sentinel binds every new unified assessment to the exact validated
intelligence policy used to produce its CVE decisions.

## Policy identity

The canonical intelligence identity contains:

- policy ID,
- schema version,
- publication date,
- canonical SHA-256.

The SHA-256 is calculated from the validated policy model using stable,
sorted JSON serialization.

Formatting or whitespace changes therefore do not alter the semantic
policy digest.

Material intelligence changes do alter the digest.

## Assessment provenance

New reports record:

- `intelligence_policy_id`,
- `intelligence_schema_version`,
- `intelligence_published_date`,
- `intelligence_sha256`.

The existing `policy_version` remains the deterministic PHP Sentinel
decision-policy version.

It is intentionally separate from vulnerability-intelligence identity.

## Canonical assessment evidence

The intelligence identity is included in the unified assessment's
canonical evidence payload.

Identical HTTP evidence interpreted under different intelligence
therefore does not produce the same canonical assessment digest.

## Schema compatibility

PHP Sentinel currently supports intelligence schema version 1.

Unsupported schema versions fail closed before the policy can influence
a security decision.

## External policy validation

Validate without activating or installing a policy:

`php-sentinel-intel --policy path/to/policy.json --validate-only`

Inspect validated policy content and canonical identity:

`php-sentinel-intel --policy path/to/policy.json --json`

Validation is non-destructive.

## Comparison safety

Pre-Phase-12 reports remain loadable because intelligence provenance
fields are optional.

If both reports contain intelligence provenance and the policy digest
differs, PHP Sentinel returns:

`policy_changed`

Per-CVE transitions remain visible, but overall remediation/regression
classification is suppressed because changed intelligence may explain
the changed conclusion.

Cross-target incompatibility remains higher priority unless explicitly
authorized with `--allow-cross-target`.

## Trust boundary

SHA-256 provides content integrity and reproducible identity.

It does not authenticate the publisher and does not prove that the
policy was authored or signed by PHP upstream.

Publisher authentication requires a separate signature/trust mechanism.
