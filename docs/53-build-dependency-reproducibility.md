# Phase 46 — Build Dependency Reproducibility

## Objective

Control the build backend versions used for release artifact generation without
turning PHP Sentinel runtime dependencies into a fully pinned application lock.

## Rationale

PHP Sentinel is distributed as a Python package. Its runtime dependency ranges
remain intentionally flexible within reviewed compatibility bounds.

Release artifact generation is different: build tooling affects package output
and should not silently change because a package index publishes a newer
setuptools or wheel release.

## Build constraints

Release builds use:

    requirements/build-constraints.txt

Current pinned build tooling:

- `setuptools==84.2.1`
- `wheel==0.48.0`

These versions match the build backend versions resolved during the Phase 46
audit.

## Reproducibility integration

`scripts/reproducible_wheel_check.py` supplies the constraints file to pip build
isolation through `PIP_CONSTRAINT` while also normalizing `SOURCE_DATE_EPOCH`.

The reproducibility check therefore controls both:

1. build timestamp input;
2. build backend package versions.

## Scope

This improves release-build determinism while preserving flexible runtime
requirements for package consumers.

It does not create a hermetic or offline build. The configured package index,
TLS trust, package availability, transitive build dependencies, and operating
system remain external inputs unless separately controlled.
