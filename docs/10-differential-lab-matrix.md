# Phase 5 — Differential PHP Laboratory

Phase 5 compares two loopback-only PHP runtimes:

- candidate runtime,
- known patched reference runtime.

Initial matrix:

| Role | PHP | Port |
|---|---|---|
| Candidate | 8.5.11 | 127.0.0.1:18081 |
| Patched reference | 8.5.12 | 127.0.0.1:18080 |

The matrix establishes deterministic security preconditions:

- PHP runtime version,
- upstream fixed-threshold state,
- HTTP process health,
- response headers,
- response-body hash,
- response length.

## Important boundary

A below-threshold runtime is a candidate for further security analysis.
It is not automatically a validated vulnerability.

Phase 5 intentionally does not contain:

- RCE payloads,
- operating-system command execution,
- memory-corruption triggers,
- crash-inducing requests,
- exploit chains.

The result `precondition_differential_confirmed` means only that the
candidate and patched reference differ across the modeled security-fix
boundary.
