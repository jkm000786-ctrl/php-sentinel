# Phase 4 — Authorization and Controlled Validation

Phase 4 introduces an explicit security boundary between passive assessment and
active validation.

## Passive assessment

Passive assessment remains suitable for explicitly authorized external targets.

## Active validation

The Phase 4 validation runner is deliberately restricted to loopback targets.

Requirements:

1. explicit authorization flag,
2. loopback-only target resolution,
3. no redirects,
4. HEAD and baseline GET only,
5. no CVE payload,
6. no command execution,
7. no memory-corruption trigger,
8. evidence captured as structured JSON.

A future CVE-specific validation implementation must sit behind this policy
boundary rather than bypassing it.

## Evidence

Validation evidence contains:

- target,
- authorization decision,
- HTTP method,
- final request URL,
- response status,
- server headers,
- body SHA-256,
- body length,
- timestamp.

This establishes reproducibility without storing arbitrary response bodies.
