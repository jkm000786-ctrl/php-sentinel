# Phase 3 — Vendor and Backport Intelligence

An upstream version banner and an operating-system package revision represent
different evidence domains.

Example:

    X-Powered-By: PHP/8.5.11

may establish an apparent upstream runtime version, but it does not prove that a
Linux distribution package lacks backported security patches.

PHP Sentinel therefore separates:

1. upstream version evidence,
2. package identity,
3. vendor identity,
4. vendor advisory evidence,
5. backport status,
6. final assessment.

## Backport states

- confirmed_fixed
- probably_fixed
- no_fix_evidence
- unknown

Only `confirmed_fixed`, supported by explicit trusted vendor/package evidence,
may produce the `patched_vendor` assessment.

`probably_fixed` is deliberately not promoted to a fact.

`no_fix_evidence` produces `potentially_affected`, not `confirmed_vulnerable`.

This distinction is fundamental to PHP Sentinel's false-positive control model.
