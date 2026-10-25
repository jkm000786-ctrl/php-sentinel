# PHP Sentinel Release Process

PHP Sentinel is currently pre-1.0.

## Release blockers

A public release must not be declared ready until:

- Ruff passes;
- the full test suite passes;
- `git diff --check` passes;
- the source tree is clean;
- the wheel builds successfully;
- packaged intelligence data is present;
- all six console entry points are present;
- CLI version output matches package metadata;
- the changelog is updated;
- security documentation reflects the release;
- a project license has been intentionally selected and added;
- release artifacts are built from a reviewed commit.

## Versioning

The canonical package version is `php_sentinel.__version__`.

Package metadata, CLI version output, evidence provenance, and runtime identity
must remain aligned with that value.

## Current status

Current development version: `0.1.0`.

This version is not yet declared a stable public release.
