# Phase 47 — GitHub Publication Foundation

## Selected governance

PHP Sentinel uses the **Apache License 2.0**.

GitHub is the selected repository host and GitHub Actions is the selected CI
platform.

## Local publication foundation

This phase establishes the provider-specific files locally before any remote
repository is created or any source is pushed.

The repository now contains:

- the canonical Apache License 2.0 text in `LICENSE`;
- package metadata referencing the license file;
- source-distribution inclusion of `LICENSE`;
- GitHub Actions CI under `.github/workflows/ci.yml`;
- Python 3.11 through 3.14 test jobs;
- a Python 3.14 release-gate job running the existing release, reproducibility,
  and sdist contracts.

## Publication boundary

This phase does **not** create a GitHub repository, configure a Git remote, push
source code, create a release tag, or publish package artifacts.

Project URLs remain unset until the actual GitHub repository identity is known.

## Next publication step

After the local gate is clean, create or connect the intended GitHub repository,
add the authoritative `origin` remote, add the repository URLs to package
metadata, verify CI remotely, and only then consider creating the `v0.1.0` tag.
