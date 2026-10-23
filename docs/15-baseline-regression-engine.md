# Phase 10 — Baseline and Regression Comparison Engine

Phase 10 compares two saved PHP Sentinel unified JSON reports.

Comparison states:

- remediated
- regressed
- unchanged
- evidence_changed
- incomparable

## Examples

Potential exposure to patched:

`potential_exposure -> patched`

is classified as:

`remediated`

Patched to potential exposure:

`patched -> potential_exposure`

is classified as:

`regressed`

## Compared material

The engine evaluates:

- PHP version,
- overall assessment state,
- per-CVE finding state,
- severity,
- SAPI hypothesis,
- response-body SHA-256,
- target-identity SHA-256,
- canonical evidence SHA-256,
- policy version,
- requested target.

## Interpretation

A target-identity change does not automatically mean regression.

It means material deployment evidence changed and should be reviewed
alongside CVE and assessment transitions.
