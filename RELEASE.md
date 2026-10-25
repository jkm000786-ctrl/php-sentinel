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
- release artifacts are built from a reviewed commit using the pinned build constraints in `requirements/build-constraints.txt`;
- repository hosting and CI policy are intentionally configured for the release.

## Versioning

The canonical package version is `php_sentinel.__version__`.

Package metadata, CLI version output, evidence provenance, and runtime identity
must remain aligned with that value.

## Current status

Current development version: `0.1.0`.

The strict local release gate is available through:

    make release-check

The development-tree variant is available through:

    make release-check-dev

The strict gate rejects dirty working trees and verifies lint, the full test
suite, diff hygiene, canonical version identity, all six CLI entry points,
wheel metadata, bundled intelligence data, build-artifact cleanup, and a fresh
wheel installation in an isolated virtual environment. The fresh-install check
also validates dependency consistency with `pip check`, installed package
version identity, packaged intelligence availability, and startup of all six
installed CLI entry points.

Public release remains blocked by two deliberate policy decisions:

1. no project license has been selected;
2. no Git remote or CI hosting platform is configured.

No provider-specific CI configuration should be added until the repository host
is intentionally chosen.

This version is not yet declared a stable public release.
