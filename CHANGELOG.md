# Changelog

All notable PHP Sentinel changes will be documented here.

## Unreleased

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
- Public-release readiness remains in progress.
- No project license has been selected yet.
