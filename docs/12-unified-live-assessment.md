# Phase 7 — Unified Live Assessment Pipeline

Phase 7 connects PHP Sentinel's existing engines into one execution path:

1. HTTP collection
2. PHP detection
3. server fingerprinting
4. SAPI hypothesis
5. PHP confidence
6. upstream version policy
7. vendor/package evidence
8. vendor backport analysis
9. per-CVE decision engine
10. unified evidence output

The implementation deliberately reuses the existing canonical modules
rather than creating a second fingerprinting or CVE-analysis stack.

## Evidence lineage

The unified JSON report records:

- requested target,
- final URL after HTTP redirects,
- HTTP status,
- redirect count,
- selected response headers,
- response body length,
- response body SHA-256,
- canonical assessment,
- CVE decisions,
- optional loopback validation report.

The arbitrary HTTP response body is not persisted.

## Active validation boundary

`scan` remains passive by default.

If `--validate-lab` is used, the existing Phase 4 scope policy is
executed first. Active validation remains restricted to explicitly
authorized loopback laboratory targets.

## Decision semantics

`potentially_affected` means that modeled CVE applicability
preconditions remain present.

It does not mean:

- exploit success,
- command execution,
- compromise,
- or a validated RCE finding.
