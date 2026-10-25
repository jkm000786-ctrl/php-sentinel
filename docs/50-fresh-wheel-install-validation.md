# Phase 46 — Fresh Wheel Installation Validation

## Objective

Prove that PHP Sentinel works from its built distribution artifact rather than
only from the editable development checkout.

## Validation model

The release-readiness gate now performs an isolated fresh-install validation:

1. build a PHP Sentinel wheel from the current source tree;
2. create a new temporary Python virtual environment;
3. install the wheel with its declared runtime dependencies;
4. run `pip check` inside that environment;
5. verify installed distribution metadata and canonical version identity;
6. read the bundled PHP intelligence resource from the installed package;
7. verify `--version` for all six installed console entry points;
8. execute `--help` for all six installed console entry points as startup smoke
   tests;
9. remove generated packaging artifacts from the source tree.

## Verified result

The Phase 46 audit proved that `php_sentinel-0.1.0-py3-none-any.whl` installs
successfully into a newly created Python 3.14 environment with all declared
runtime dependencies.

The installed package reports version `0.1.0`, the packaged intelligence
resource is present and non-empty, all six installed CLI commands report the
canonical version and start successfully, and `pip check` reports no broken
requirements.

## Release-gate integration

This validation is implemented by `verify_fresh_install()` in
`scripts/release_check.py` and is executed by both:

    make release-check

and:

    make release-check-dev

The strict variant still requires a clean Git working tree before release
validation begins.

## Scope

This proves installation and CLI startup for the wheel on the current supported
POSIX/WSL development environment. It does not claim equivalent Windows-native
filesystem security semantics, offline dependency reproducibility, or testing
across every Python version permitted by `requires-python`.

Those are separate compatibility and release-governance concerns and must not be
inferred from this validation.
