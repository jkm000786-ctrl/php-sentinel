# Security Policy

## Scope

Security reports should concern PHP Sentinel itself, including trust-boundary
bypasses, unsafe active-validation behavior, intelligence-verification flaws,
authority-state integrity failures, cache-integrity failures, or filesystem
security defects.

## Reporting

Do not publicly disclose suspected PHP Sentinel security vulnerabilities before
maintainers have had a reasonable opportunity to investigate them.

Until a dedicated private reporting channel is published, do not place exploit
details, credentials, private target information, or weaponized proof-of-concept
material in public reports.

## Testing constraints

PHP Sentinel does not grant authorization to assess third-party systems.

Only assess systems you own or are explicitly authorized to test. Public active
validation remains outside the intended behavior; active validation is restricted
to explicitly authorized local laboratory targets.

## Supported versions

PHP Sentinel is currently pre-1.0. Security fixes apply to the current
development line unless a release-specific support policy is published.

## Design references

See `docs/02-threat-model.md` and
`docs/48-v1-security-review-threat-model-closure.md`.
