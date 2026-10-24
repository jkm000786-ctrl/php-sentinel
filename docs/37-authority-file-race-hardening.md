# Phase 32 — Authority File Race & Symlink Hardening

Phase 32 extends local filesystem hardening from verified-cache objects to the
files that directly influence trust and lifecycle authority.

## Scope

This phase covers:

- intelligence TrustStore reads;
- intelligence lifecycle-state reads;
- source-registry lifecycle-state reads;
- lifecycle-state temporary writes;
- source-registry lifecycle-state temporary writes.

It intentionally preserves the existing:

- lifecycle locks;
- compare-and-swap state checks;
- atomic `os.replace` persistence;
- directory fsync behavior;
- lifecycle and delegation semantics.

## TrustStore reads

TrustStore loading previously used ordinary pathname text reads.

Phase 32 now opens the TrustStore with low-level descriptor semantics using:

- `os.open`;
- `O_NOFOLLOW` where available;
- `O_CLOEXEC` where available;
- `os.fstat`.

The opened object must be a regular file.

A symbolic-link TrustStore fails closed before JSON parsing or trust evaluation.

This prevents authority substitution through a direct TrustStore symlink.

## Lifecycle-state reads

Lifecycle-state loading previously used:

`exists() -> read_text()`

which contains a pathname race and follows symbolic links.

Phase 32 replaces that sequence with a single low-level open operation.

The loader now:

1. attempts to open the lifecycle-state file directly;
2. treats `FileNotFoundError` as an empty initial state;
3. uses `O_NOFOLLOW` where supported;
4. verifies the opened object with `fstat`;
5. requires a regular file;
6. reads the exact opened descriptor;
7. parses and validates that exact byte snapshot.

Symlinked or non-regular lifecycle-state objects fail closed.

## Source-registry state reads

Source-registry lifecycle state receives the same treatment:

- no preliminary `exists()` check;
- descriptor-based open;
- no-follow semantics where available;
- regular-file validation with `fstat`;
- exact descriptor byte read;
- model validation from those bytes.

Missing state still represents a new empty registry lifecycle state.

## Temporary-file write hardening

Lifecycle and registry state persistence already used:

`write temporary -> fsync -> os.replace -> directory fsync`

which provides strong atomic replacement semantics.

However, deterministic temporary paths ending in `.tmp` were opened with
`O_TRUNC`.

If a local attacker pre-created the temporary pathname as a symlink, the write
could follow that link and truncate or overwrite another file before the final
`os.replace`.

Phase 32 preserves the existing atomic-write architecture but adds:

- `O_NOFOLLOW` where available;
- `O_CLOEXEC` where available;

to lifecycle and registry temporary-file opens.

A symlinked temporary file therefore fails closed rather than being followed.

## CAS and locking semantics retained

This phase does not alter the established lifecycle concurrency model.

Authoritative mutations still:

1. acquire the lifecycle-state lock;
2. reload current state;
3. compare current state against the evaluated snapshot;
4. reject concurrent changes;
5. construct the updated state;
6. write a temporary file durably;
7. atomically replace the authority file;
8. fsync the containing directory where supported.

Delegation revocation history and accepted lifecycle history therefore keep the
same persistence semantics.

## Security invariants

Phase 32 establishes:

1. TrustStore authority files are not accepted through direct symlinks.
2. Lifecycle-state authority files are not accepted through direct symlinks.
3. Registry lifecycle-state authority files are not accepted through direct
   symlinks.
4. Authority-state reads operate on the exact descriptor that was validated.
5. Authority-state files must be regular files.
6. Missing lifecycle/registry state retains the existing empty-state behavior.
7. Deterministic lifecycle temporary files cannot be followed through symlinks
   when `O_NOFOLLOW` is supported.
8. Deterministic registry temporary files receive the same protection.
9. Existing lock, CAS, atomic-replace, and fsync semantics remain intact.
10. This phase does not make lifecycle state cryptographically tamper-evident.

## Remaining limits

This phase improves direct file-object identity but does not claim complete
hostile-local-process resistance.

Remaining considerations include:

- parent-directory substitution before an individual file descriptor is
  obtained;
- lifecycle lock-file pathname handling;
- stale-lock inspection/removal behavior;
- source-registry and signed-registry input files outside the lifecycle-state
  authority store;
- cryptographic tamper evidence for persisted lifecycle state;
- platform behavior where POSIX descriptor flags are unavailable.

These are separate hardening surfaces and should not be conflated with the
direct authority-file protections delivered here.

## Result

The local authority path now follows the pattern:

`authority pathname -> no-follow descriptor open -> regular-file fstat ->
exact byte snapshot -> model validation -> trust/lifecycle logic`

while durable state writes retain:

`lock -> CAS -> no-follow temporary write -> fsync -> atomic replace ->
directory fsync`.
