# Changelog

All notable PHP Sentinel changes will be documented here.


## Unreleased

### Security

- Integrated passive edge/WAF classification into the canonical unified assessment authority path before PHP, SAPI, CVE, and finding conclusions are accepted.
- Edge responses, WAF blocks, bot challenges, rate limits, and recognized origin failures now fail closed to an `inconclusive` application assessment when application reachability is `unknown` or `not_reached`.
- Bound edge provider, response class, application reachability, challenge/rate-limit state, and ambiguity into canonical assessment provenance and target identity.
- Added cross-layer invariants preventing edge-gated evidence from coexisting with potential-exposure or other non-inconclusive CVE/finding conclusions.
- Hardened passive edge-provider attribution with explicit ambiguity handling so conflicting strong provider signals fail to `unknown` instead of forcing a single attribution.
- Added conservative passive fingerprints for AWS CloudFront, Sucuri, and Azure edge infrastructure while preserving the distinction between CDN evidence and WAF evidence.
- Reduced edge/WAF false positives: generic 403 and generic rejection text no longer establish a WAF, and edge-only responses remain application-reachability `unknown` without independent PHP evidence.
- Sanitized opaque edge request identifiers from retained edge signal evidence.
- Added a passive Edge Security Intelligence foundation that distinguishes application responses from CDN/WAF challenges, explicit WAF blocks, rate limiting, and edge-origin failures without introducing public-target evasion behavior.
- Added evidence-weighted provider classification for Cloudflare, Akamai, Imperva, Fastly, BunnyCDN, ModSecurity, and conservative generic edge/WAF signals.
- Clarified the canonical intelligence authority boundary: `php-sentinel scan` is provenance-bearing, while `analyze` and `php-sentinel-cve` are explicitly diagnostic bundled-policy surfaces.
- Removed the legacy CVE database module-level policy object so no persistent default intelligence policy object remains outside the repository template cache.
- Isolated bundled intelligence policy state so mutating one retrieved default policy cannot poison later security decisions.
- Bound differential laboratory validation to the same verified intelligence selection and provenance model used by authoritative assessment paths.

### Fixed

- Enforced canonical consistency across assessment status, per-CVE decisions, exposure priority, findings, and remediation.
- Cleared exposure priority for non-PHP and vendor-patched assessment states.

## 0.1.2 - 2026-10-25

### Fixed

- Require explicit server evidence for FrankenPHP SAPI inference so documentation/body mentions cannot produce high-confidence runtime fingerprints.
- Reject response-body-only PHP-FPM, FastCGI, and CGI SAPI markers to reduce false positives on documentation-heavy sites.
- Derive Python compatibility-matrix version assertions from the canonical package version instead of a stale hardcoded release value.

## 0.1.1 - 2026-10-25

### Fixed

- Disabled HTTP response compression negotiation for passive scans to avoid real-world decompression failures observed during field validation.
- Added regression coverage for the `Accept-Encoding: identity` transport invariant.

## 0.1.0 - 2026-10-25

### Security

- Completed the v1 threat-model closure and residual-risk review.
- Hardened signed intelligence, registry, lifecycle, cache, filesystem, and
  authenticated authority-state handling.
- Added end-to-end adversarial supply-chain coverage.
- Bound registry authorization to the exact verified cache entry selected for
  activation.

### Changed

- Centralized package version identity.
- Added `--version` to all six installed CLI entry points.
- Runtime HTTP user agents derive from the canonical package version.
- Removed unsupported environment-variable configuration promises.

### Release status

- Version remains `0.1.0`.
- Public-release readiness checks are complete.
- Licensed under Apache-2.0 and published on GitHub.
