# Changelog

All notable PHP Sentinel changes will be documented here.

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
