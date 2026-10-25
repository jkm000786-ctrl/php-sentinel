# Phase 46 — Reproducible Wheel Build

## Objective

Verify that PHP Sentinel can produce a byte-identical wheel from the same source
state when build timestamps are normalized.

## Method

Two independent wheel builds are executed with a fixed `SOURCE_DATE_EPOCH`.
The audit then compares:

1. wheel filenames;
2. SHA-256 digests of the complete wheel archives;
3. complete wheel bytes;
4. archive member ordering;
5. SHA-256 digests of every extracted member.

## Verified result

The audited `php_sentinel-0.1.0-py3-none-any.whl` builds were byte-identical.
Both builds produced the same SHA-256 digest, the same archive member ordering,
and identical extracted file contents.

## Repeatable check

Run:

    make reproducible-wheel

The check uses a fixed `SOURCE_DATE_EPOCH` and fails closed if the two builds
differ at any verified layer.

## Scope

This demonstrates reproducibility under the same source tree, build backend,
dependency-resolution environment, and normalized build timestamp.

It does not claim hermetic or offline reproducibility across different build
backend versions, operating systems, dependency indexes, or supply-chain
mirrors. Those require additional dependency-locking and build-environment
controls.
