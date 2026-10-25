# Phase 46 — Source Distribution Release Readiness

## Objective

Validate PHP Sentinel source-distribution contents, rebuildability, and consumer
installation without leaking build-only constraints into runtime dependency
resolution.

## Manifest

`MANIFEST.in` explicitly includes the release-governance files required in the
source distribution:

- `README.md`
- `SECURITY.md`
- `RELEASE.md`
- `CHANGELOG.md`
- `requirements/build-constraints.txt`
- bundled intelligence JSON resources

## Build/runtime constraint separation

Build tooling and runtime dependencies are separate contracts.

The sdist build uses an isolated environment with the audited build-tool
versions. Wheel rebuilding from the sdist uses pip `--build-constraint` so the
build dependency graph is constrained without applying those versions to PHP
Sentinel runtime dependencies.

Consumer installation intentionally does not use the build constraints as a
runtime constraint file.

## Repeatable verification

Run:

    make sdist-check

The check validates required archive members, rebuilds a wheel from the sdist,
performs a fresh consumer installation, runs `pip check`, verifies package
version and bundled intelligence, and starts all six CLI entry points.
