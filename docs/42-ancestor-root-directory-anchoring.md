# Phase 37 — Ancestor and Root Directory Anchoring

## Scope

Phase 37 extends PHP Sentinel's descriptor-based authority-storage hardening
from the final state directory to every pathname component used to reach that
directory.

The protected local authority paths include:

- intelligence lifecycle state;
- source-registry lifecycle state;
- the local authority-state HMAC key.

## Problem

Phase 34 retained one open descriptor for the final lifecycle-state directory
during a transaction.

That prevented a later rename or replacement of that final directory pathname
from redirecting:

`lock -> reload -> CAS -> temporary write -> rename`

However, obtaining the final directory descriptor still depended on ordinary
pathname resolution for ancestors.

Likewise, Phase 36 authority-key creation used recursive pathname-based parent
creation before applying final-file `O_NOFOLLOW` protection.

A symbolic-link ancestor could therefore redirect resolution before the final
directory or key file was opened.

## Anchored component traversal

Phase 37 introduces a reusable directory traversal primitive.

For an absolute authority path, traversal begins with an opened descriptor for
`/`.

For a relative authority path, traversal begins with an opened descriptor for
the current working directory.

Each subsequent component is opened relative to the already-open parent
descriptor with:

- `O_DIRECTORY` where supported;
- `O_NOFOLLOW` where supported;
- `O_CLOEXEC` where supported.

Each opened component is verified with `fstat` and must be a directory.

The complete parent pathname is therefore not repeatedly resolved as one
string.

## Safe directory creation

When creation is requested, missing directories are created one component at a
time with descriptor-relative `mkdir`.

After creation, the component is reopened through the same parent descriptor
and must independently pass the no-follow directory checks.

If another process creates the component concurrently, PHP Sentinel does not
trust that event. It reopens and validates the resulting object.

## Parent traversal

Explicit `..` components are rejected.

Authority-storage callers therefore cannot use the anchored walker to escape
upward from the selected traversal root.

`.` and empty components are normalized away.

## Lifecycle and registry state

The existing `_StateDirectoryAnchor` transaction model is retained.

The difference is how its initial directory descriptor is obtained.

Phase 37 now performs:

`root fd -> component fd -> ... -> state-directory fd`

before beginning:

`relative lock -> anchored reload -> CAS -> temporary write -> relative rename`

The Phase 34 property that one final directory descriptor remains bound for the
whole transaction is unchanged.

## Authority key

Authority-key reads now:

1. obtain the parent directory through anchored component traversal;
2. open the key basename relative to that directory descriptor;
3. request `O_NOFOLLOW`;
4. verify the file with `fstat`;
5. require a regular file.

Authority-key generation now:

1. creates/opens the parent hierarchy through anchored traversal;
2. creates the key basename relative to the final directory descriptor;
3. uses `O_CREAT | O_EXCL`;
4. uses `O_NOFOLLOW` where supported;
5. verifies the created object with `fstat`;
6. fsyncs the key;
7. fsyncs the already-open parent directory descriptor.

The parent directory is no longer reopened by pathname for durability sync.

## Error contract

Traversal failures fail closed as `DirectoryAnchorError`.

This includes:

- symbolic-link components;
- non-directory components;
- permission failures;
- unsafe component opens;
- unsafe component creation or reopen;
- invalid parent traversal.

Lifecycle and authority-key layers translate this primitive failure into their
existing storage-domain errors.

## Adversarial coverage

Phase 37 adds tests covering:

- symlinked state ancestors;
- symlinked key ancestors;
- state read through a symlinked ancestor;
- key read through a symlinked ancestor;
- rejection of `..` state paths;
- rejection of `..` key paths;
- nested descriptor-relative directory creation;
- non-directory ancestor rejection;
- normalization of unexpected component-open OS errors;
- retained Phase 34 final-directory rename/replacement protection.

## Security invariants

Phase 37 establishes:

1. Authority path ancestors are traversed descriptor-relative.
2. Existing ancestor symbolic links are not followed where POSIX no-follow
   semantics are available.
3. Missing directories are created relative to an already-open parent.
4. Newly created or concurrently created components are reopened and verified.
5. Explicit parent traversal is rejected.
6. Lifecycle state keeps one anchored final directory descriptor per mutation
   transaction.
7. Registry lifecycle state inherits the same directory traversal semantics.
8. Authority-key reads operate relative to an anchored parent descriptor.
9. Authority-key creation operates relative to an anchored parent descriptor.
10. Authority-key parent fsync uses that same descriptor rather than pathname
    reopening.
11. Final state files, lock files, temporary files, and key files retain their
    earlier no-follow and regular-file checks.

## Important non-claims

Phase 37 does not claim protection against a process with sufficient privilege
to manipulate:

- mount namespaces;
- mounted filesystems below already-open descriptors;
- kernel filesystem behavior;
- the process itself;
- both authenticated state and its independent HMAC key.

The implementation also depends on POSIX-style `dir_fd`, `O_DIRECTORY`, and
`O_NOFOLLOW` semantics for its strongest guarantees.

Cross-platform equivalence remains separate hardening work.

## Result

Authority storage now resolves directories using:

`trusted traversal start -> descriptor-relative component walk -> anchored final
directory -> descriptor-relative authority file operations`

rather than trusting ordinary recursive pathname resolution to reach the final
authority directory.
