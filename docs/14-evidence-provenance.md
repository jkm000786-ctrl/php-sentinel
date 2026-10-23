# Phase 9 — Evidence Hardening and Reproducibility

Phase 9 gives every unified PHP Sentinel assessment an explicit
provenance envelope.

Each report records:

- unique report ID,
- PHP Sentinel package version,
- decision-policy version,
- canonical evidence SHA-256,
- target-identity SHA-256,
- generation timestamp.

## Canonical evidence hash

The canonical SHA-256 is calculated over stable assessment material:

- target,
- HTTP metadata,
- PHP assessment,
- CVE decisions,
- findings.

The unique report ID, generation timestamp, and nested observation
timestamps are intentionally excluded from that digest so equivalent
material evidence produces the same canonical evidence hash.

Volatile audit metadata remains present in the report itself; it is
excluded only from canonical evidence-equivalence hashing.

## Target identity hash

Target identity is derived from:

- requested URL,
- final URL,
- server header,
- PHP version,
- response-body SHA-256.

It provides a compact identifier for comparing observations of the
same deployment over time.

## Purpose

These hashes are evidence-integrity and comparison mechanisms.

They are not digital signatures and do not independently prove who
collected the evidence.
