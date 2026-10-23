# Phase 11 — Data-Driven Vulnerability Intelligence

PHP Sentinel separates vulnerability intelligence from deterministic
decision logic.

## Intelligence policy

The bundled default policy is:

`src/php_sentinel/data/intelligence/php-2026-10-critical.json`

It contains:

- policy schema version,
- policy identity,
- publication date,
- source metadata,
- modeled CVEs,
- upstream fixed-version thresholds,
- SAPI exposure-priority groups,
- generic remediation guidance,
- CVE-specific temporary mitigations,
- interpretation notes.

## Validation

The JSON document is validated through Pydantic models before use.

Validation includes:

- CVE identifier format,
- unique CVE identifiers,
- fixed-version syntax,
- branch/fixed-version consistency,
- SAPI-priority group consistency,
- required policy metadata.

Malformed policy data fails closed rather than silently influencing a
security assessment.

## Deterministic boundary

Policy data supplies facts and configuration such as fixed thresholds,
CVE identity, SAPI categories, and remediation text.

Python code retains deterministic decision semantics for:

- patched upstream,
- patched vendor,
- potentially affected,
- vendor evidence required,
- not applicable,
- inconclusive.

Changing policy data does not introduce arbitrary executable rules.

## Backward compatibility

`cve_database.py` remains as a compatibility facade for existing code.

Its `OCT_2026_CRITICAL` and `FIXED_UPSTREAM` values are now derived from
the validated intelligence policy rather than independently hardcoded.

## Policy inspection

Use:

`php-sentinel-intel`

An alternate policy can be validated and displayed with:

`php-sentinel-intel --policy path/to/policy.json`

## Security interpretation

A modeled vulnerable-range result remains an applicability assessment.

It does not establish command execution, memory corruption, compromise,
or successful exploitation.
