# Phase 8 — Finding and Reporting Engine

Phase 8 converts deterministic CVE decisions into defensible
security findings.

Finding states:

- patched
- potential_exposure
- needs_evidence
- not_applicable
- inconclusive

PHP Sentinel does not currently produce a `validated_exploit` state.

The present laboratory validates version, deployment, authorization,
and applicability conditions. It does not execute a remote-code
execution payload.

## Severity

Severity and evidence state are separate dimensions.

A CVE can have critical upstream security impact while PHP Sentinel
still labels the evidence state as `potential_exposure`.

This prevents impact severity from being confused with proof of
successful exploitation.

## Reporting

Unified scans can emit:

- structured JSON evidence,
- Markdown technical reports.

The Markdown report contains:

- executive summary,
- HTTP evidence integrity,
- individual CVE findings,
- evidence,
- rationale,
- remediation,
- interpretation boundaries.
