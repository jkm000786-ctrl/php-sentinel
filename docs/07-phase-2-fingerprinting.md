# Phase 2 — Fingerprinting and Applicability

Phase 2 adds:

- web server family detection,
- SAPI hypothesis generation,
- PHP detection confidence,
- deployment-aware CVE applicability,
- exposure priority.

Important limitation:

SAPI identification from remote HTTP evidence is probabilistic unless explicit
runtime evidence is disclosed. Apache + PHP does not prove mod_php, and nginx +
PHP does not prove PHP-FPM. These are hypotheses with confidence scores.

The tool must preserve this distinction.
