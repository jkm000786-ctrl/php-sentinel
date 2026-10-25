# Phase 46 — Release Governance Closure

## Status

Phase 46 technical release engineering is complete for PHP Sentinel `0.1.0`.

The project remains classified as **Alpha** and is **not yet declared ready for
public release** because two governance decisions are intentionally unresolved.

## Validated release properties

The Phase 46 audit established and repeatedly verified:

- one canonical package version identity (`0.1.0`);
- wheel packaging and bundled intelligence resources;
- fresh wheel installation with declared runtime dependencies;
- CLI startup and version identity for all six entry points;
- Python 3.11, 3.12, 3.13, and 3.14 compatibility through isolated Docker
  smoke validation;
- byte-identical wheel reproduction under the documented normalized build
  environment;
- pinned build-tool dependency graph for release artifact generation;
- source-distribution contents, wheel rebuildability, fresh consumer install,
  resource availability, and CLI startup;
- strict clean-tree release gating;
- release, security, changelog, manifest, and build-governance documentation.

## Repeatable technical gates

The release-engineering contract is represented by these commands:

    make release-check
    make reproducible-wheel
    make sdist-check
    make python-matrix

`make release-check` is the ordinary strict local release gate. The Python
matrix is intentionally separate because it requires Docker.

## Remaining public-release blockers

Only the following deliberate governance decisions remain:

1. **License selection** — no project license has been selected, and no license
   should be inferred or invented.
2. **Repository hosting and CI policy** — no Git remote or CI provider has been
   selected or configured, so provider-specific workflow files must not be
   added by assumption.

These are policy/ownership decisions rather than unresolved packaging defects.

## Explicit non-claims

Phase 46 does not claim:

- stable (`1.0`) release status;
- hermetic or fully offline dependency reproduction;
- universal operating-system security equivalence;
- support beyond the explicitly tested Python interpreter matrix;
- public redistribution or modification rights before a license is selected;
- repository-host or CI-provider support before those choices are made.

## Closure decision

Phase 46 is closed as **technically complete, governance-blocked for public
publication**.

No license, project URL, Git remote, or CI provider is selected by this closure.
