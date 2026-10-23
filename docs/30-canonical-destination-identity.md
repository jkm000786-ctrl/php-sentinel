# Phase 25 — Canonical Destination Identity & Edge-Case Hardening

Phase 25 hardens the trusted intelligence update transport against ambiguous
network and URL identities that could weaken destination-policy or
source-containment decisions.

## Objective

Phase 24 already enforced signed-registry authority, HTTPS-only updates,
redirect refusal, public-destination DNS preflight, connected-peer verification,
and structural source URL containment.

Phase 25 strengthens the canonical identity rules used by those controls.

## IPv4-mapped IPv6

PHP Sentinel rejects all IPv4-mapped IPv6 update destinations, including:

- `::ffff:127.0.0.1`
- `::ffff:10.0.0.1`
- `::ffff:8.8.8.8`

This applies even when the mapped IPv4 address is globally routable.

The policy deliberately avoids allowing the same network identity to participate
in trust decisions through multiple address-family representations.

## Scoped IPv6

Scoped or percent-bearing host identities are rejected for intelligence update
transport.

Examples include IPv6 zone identifiers such as:

`fe80::1%eth0`

and percent-encoded zone representations.

Interface-local addressing therefore cannot become a remote publisher authority.

## Malformed ports

Malformed or out-of-range URL ports fail with
`IntelligenceUpdateTransportError`.

Raw URL-parser `ValueError` exceptions do not escape the transport-policy
boundary.

Source-registry containment also fails closed when an authority contains an
invalid port.

## Structural path ambiguity

Source URL containment rejects path representations whose decoding could alter
hierarchy.

Rejected structural encodings include encoded forms of:

- dot;
- slash;
- backslash;
- percent.

Examples include:

- `%2e%2e`
- `%2f`
- `%5c`
- `%25`

Literal `.` and `..` path segments are also rejected.

Non-structural percent encodings such as `%20` remain permitted.

## Registry model layering

The source-registry model already rejects:

- absolute channel paths;
- literal `.` segments;
- literal `..` segments;
- empty path segments;
- URL schemes;
- network authorities;
- query strings;
- fragments.

Phase 25 adds resolution-time protection against encoded structural ambiguity.

The effective pipeline is:

`registry model validation -> urljoin -> structural containment -> transport policy`

No individual parser or validator is treated as the complete security boundary.

## Fail-closed semantics

Ambiguous destination identity is rejected rather than normalized permissively.

This applies to:

- IPv4-mapped IPv6;
- scoped IPv6;
- malformed ports;
- encoded path traversal.

The objective is deterministic authority comparison.

## Security invariants

Phase 25 adds these invariants:

1. IPv4-mapped IPv6 update destinations are rejected.
2. Scoped or percent-bearing host identities are rejected.
3. Malformed ports become controlled transport-policy failures.
4. Encoded path structure capable of changing hierarchy is rejected.
5. Literal and encoded hierarchy escapes are both denied.
6. Registry model validation and resolution-time containment remain independent
   defensive layers.
7. Canonical destination identity is preferred over alternate equivalent textual
   representations.

## Result

The trusted update channel now applies stricter canonical destination identity
across IP families, scoped IPv6, URL authority parsing, and encoded paths.

The Phase 24 trust rule remains unchanged:

`transport success != intelligence trust`
