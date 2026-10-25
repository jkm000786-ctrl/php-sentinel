# Phase 46 — Python Compatibility Matrix

## Objective

Validate the declared `requires-python >=3.11` contract across the currently
supported Python minor versions rather than inferring compatibility from the
Python 3.14 development environment alone.

## Matrix

PHP Sentinel was validated from the built wheel in isolated official Python
Docker images for:

- Python 3.11
- Python 3.12
- Python 3.13
- Python 3.14

For each version the audit verified:

1. wheel installation with declared runtime dependencies;
2. `pip check` dependency consistency;
3. installed distribution version `0.1.0`;
4. package `__version__` identity;
5. bundled intelligence resource availability;
6. `--version` for all six installed CLI entry points;
7. `--help` startup for all six installed CLI entry points.

All four versions passed.

## Repeatable check

The compatibility matrix is available through:

    make python-matrix

This check requires a working Docker daemon and is intentionally separate from
`make release-check` so the ordinary local release gate does not acquire a
mandatory Docker dependency.

## Support statement

The project may retain `requires-python = \">=3.11\"` based on the validated
3.11 through 3.14 matrix.

This matrix demonstrates package installation and CLI startup compatibility. It
does not by itself prove equivalent filesystem-security semantics across
non-POSIX operating systems or future Python releases beyond those explicitly
tested.
