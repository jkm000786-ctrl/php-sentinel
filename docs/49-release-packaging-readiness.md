# Phase 45 — Release and Packaging Readiness Audit

## Objective

Evaluate whether PHP Sentinel is ready to move from a security-complete
pre-release codebase to a reproducible public release process.

## Baseline

Phase 45 began with the security architecture and v1 threat-model review
complete, but package version `0.1.0` still appeared in multiple runtime
locations and the repository had no release-governance or release-automation
layer.

## Findings and closures

### 1. Package-version identity drift

The package version was duplicated across package metadata, `__version__`, HTTP
user agents, and the local validator user agent.

Closure:

- `php_sentinel.__version__` is the canonical version source;
- setuptools reads the project version dynamically from that value;
- runtime user agents derive from the same canonical version;
- all six installed CLI entry points expose `--version`;
- regression coverage verifies package metadata and CLI identity alignment.

### 2. Unsupported environment-variable contract

`.env.example` advertised timeout and user-agent variables that the runtime did
not consume.

Closure:

- the unsupported configuration promise was removed;
- runtime configuration remains explicit through CLI options and function
  arguments unless a future environment contract is intentionally designed.

### 3. Package metadata and governance gaps

The built wheel lacked README long-description metadata and author identity, and
the repository lacked release/security/changelog governance.

Closure:

- README is used as the package long description;
- package metadata includes author identity, keywords, classifiers, and Python
  support metadata;
- `SECURITY.md`, `CHANGELOG.md`, and `RELEASE.md` define the current governance
  baseline;
- no license was invented or selected during the audit.

### 4. Manual-only release verification

Release readiness previously depended on manually repeating lint, tests, version
checks, and wheel inspection.

Closure:

- `scripts/release_check.py` provides one repeatable release gate;
- `make release-check` requires a clean working tree;
- `make release-check-dev` validates an intentionally dirty development tree;
- the gate verifies Ruff, the full test suite, `git diff --check`, canonical
  version identity, all six CLI version surfaces, wheel naming and metadata,
  bundled intelligence data, console entry points, and build-artifact cleanup;
- strict mode was explicitly tested to reject a dirty tree and pass again after
  cleanup.

## Verified state

At Phase 45 closure:

- Ruff passes;
- 566 tests pass;
- strict release checking passes from a clean committed tree;
- dirty-tree rejection is proven;
- the wheel builds as `php_sentinel-0.1.0-py3-none-any.whl`;
- all six console entry points are present;
- packaged intelligence data is present;
- release checking leaves no `build/`, `dist/`, or generated egg-info artifacts.

## Deliberate public-release blockers

PHP Sentinel is not yet declared public-release ready because two decisions are
outside the scope of an automatic code change:

1. **License selection** — no project license has been intentionally chosen.
2. **Repository hosting / CI provider** — the Git repository has no remote and no
   configured CI platform.

Provider-specific CI must not be added by assumption. Once a repository host is
chosen, CI should invoke the existing release-check contract rather than
reimplementing independent release logic.

## Release status

Phase 45 closes the technical packaging and local release-readiness audit.

The codebase remains version `0.1.0`, pre-1.0, and not yet a stable public
release. The remaining blockers are explicit governance decisions rather than
unresolved packaging defects.
