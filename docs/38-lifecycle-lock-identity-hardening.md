# Phase 33 — Lifecycle Lock-File Identity & Stale-Lock Race Hardening

Phase 33 hardens the lifecycle-state lock used by both intelligence lifecycle
state and source-registry lifecycle state.

## Problem

Before this phase, stale-lock recovery used separate pathname operations:

`stat(lock path) -> read_text(lock path) -> unlink(lock path)`

A concurrent local process could replace the lock between those operations.

That could cause PHP Sentinel to inspect one lock object but unlink another.

The lock creation path also did not request `O_NOFOLLOW`.

Final lock cleanup similarly unlinked the pathname without verifying that the
pathname still referred to the lock object originally acquired by the current
process.

## Descriptor-bound stale-lock inspection

Phase 33 opens an existing lock using low-level descriptor semantics:

- `os.open`;
- `O_NOFOLLOW` where available;
- `O_CLOEXEC` where available;
- `os.fstat`.

The lock must be a regular file.

The lock-owner JSON is read from that exact descriptor rather than reopening
the pathname.

The descriptor therefore binds:

- lock age;
- lock contents;
- owner PID;
- device identity;
- inode identity;

to the same opened object.

## Owner liveness

The PID read from the lock snapshot retains the existing liveness model:

- missing, malformed, non-positive, or dead PID -> not live;
- `ProcessLookupError` -> not live;
- `PermissionError` -> treated as live;
- ambiguous platform `OSError` -> treated as live;
- successful process probe -> live.

This preserves conservative lock ownership behavior.

## Identity-checked stale-lock deletion

A stale lock is removed only after:

1. opening and validating the lock object;
2. reading its owner from the same descriptor;
3. determining the lock is old enough;
4. determining the owner is not live;
5. obtaining the current pathname identity without following symlinks;
6. comparing current `(st_dev, st_ino)` with the opened snapshot;
7. unlinking only when the identity still matches.

If another process replaces the lock before deletion, the identity comparison
fails and PHP Sentinel does not unlink the replacement.

The caller then retries or waits according to the existing bounded lock
behavior.

## Lock creation

Exclusive lock creation retains:

- `O_CREAT`;
- `O_EXCL`;

and now additionally uses:

- `O_NOFOLLOW` where available;
- `O_CLOEXEC` where available.

The newly created lock is immediately validated with `fstat` and must be a
regular file.

## Lock cleanup

The process now records the device/inode identity of the lock it actually
created.

When leaving the lock context, cleanup compares the current pathname object to
that recorded identity.

If the lock pathname has been deleted and replaced during the critical
section, PHP Sentinel does not unlink the replacement.

This prevents final cleanup from deleting another process's lock.

## Symlink and non-regular lock handling

Direct symlink lock objects fail closed.

Non-regular lock objects such as directories also fail closed.

Stale-lock handling therefore no longer treats arbitrary filesystem objects as
valid lifecycle lock files.

## Concurrency semantics retained

Phase 33 does not alter the higher-level state concurrency model.

Lifecycle and registry state mutation still uses:

`lock -> reload current state -> compare expected snapshot -> mutate ->
durable temporary write -> atomic replace -> directory fsync`

The phase only strengthens the lock object's filesystem identity.

## Security invariants

Phase 33 establishes:

1. Existing lock contents are read from the same descriptor used for age and
   identity inspection.
2. Direct lock symlinks fail closed where no-follow semantics are available.
3. Lock objects must be regular files.
4. Stale-lock removal requires the current pathname to still reference the
   same device/inode as the inspected stale lock.
5. A replacement lock is not removed during stale-lock recovery.
6. A replacement lock is not removed during final context cleanup.
7. Exclusive lock creation retains `O_EXCL`.
8. Existing lock timeouts and stale-owner recovery semantics remain intact.
9. Lifecycle and registry state continue to share the same hardened lock
   implementation.
10. This phase does not make lifecycle state cryptographically tamper-evident.

## Remaining limits

This phase does not claim perfect hostile-local-filesystem resistance.

Remaining considerations include:

- parent-directory substitution before the lock pathname is opened;
- pathname replacement between the final identity check and the kernel
  `unlink` operation;
- lack of a root-directory descriptor anchoring the entire state namespace;
- platform differences where POSIX no-follow behavior is unavailable;
- local actors with sufficient privileges to manipulate process identities or
  the containing filesystem;
- cryptographic tamper evidence for lifecycle and registry state.

A future hardening phase could anchor state, temporary, and lock operations
under an already-open state-directory descriptor and use `dir_fd` operations
throughout.

## Result

Stale-lock handling now follows:

`no-follow lock open -> fstat identity -> exact descriptor read -> owner
liveness -> no-follow current identity -> dev/inode comparison -> unlink`

and lock cleanup follows:

`record acquired dev/inode -> critical section -> current identity check ->
unlink only if identity still matches`.
