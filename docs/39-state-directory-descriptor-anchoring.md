# Phase 34 — State Directory Descriptor Anchoring

Phase 34 extends local authority-file hardening from individual files to the
directory namespace that contains lifecycle and source-registry state.

## Problem

Earlier hardening phases protected:

- state files with `O_NOFOLLOW`;
- temporary files with `O_NOFOLLOW`;
- lock files with descriptor-bound inspection;
- stale-lock removal with device/inode checks.

However, those operations still resolved the state directory pathname
independently.

A concurrent local filesystem actor could therefore rename or replace the
parent directory between:

`lock acquisition -> state reload -> CAS -> temporary write -> rename`

causing different stages of one logical transaction to operate in different
directory namespaces.

## Directory anchor

Phase 34 introduces a state-directory anchor.

At the beginning of a mutation transaction PHP Sentinel:

1. creates the parent directory when required;
2. opens the directory itself;
3. requests `O_DIRECTORY` where available;
4. requests `O_NOFOLLOW` where available;
5. requests `O_CLOEXEC` where available;
6. verifies the opened descriptor with `fstat`;
7. requires the opened object to be a directory;
8. retains that directory descriptor for the entire transaction.

Lifecycle and source-registry state use the same anchoring model.

## Relative lock operations

Lifecycle lock creation and inspection now operate relative to the open
directory descriptor.

Lock creation uses:

- `O_CREAT`;
- `O_EXCL`;
- `O_NOFOLLOW` where available;
- `O_CLOEXEC` where available;
- `dir_fd=<anchored state directory>`.

Existing-lock inspection also opens relative to the same directory descriptor.

Stale-lock stat and unlink operations are descriptor-relative.

This preserves the Phase 33 device/inode identity checks while additionally
binding the lock pathname to one directory namespace.

## Anchored lifecycle-state reads

Lifecycle state loaded during a mutation transaction is opened by basename
relative to the same directory descriptor used for the lock.

The CAS sequence is therefore:

`anchored lock -> anchored state reload -> compare expected snapshot`

rather than resolving the state parent path again after lock acquisition.

Standalone lifecycle-state reads open their own short-lived directory anchor.

## Anchored lifecycle-state writes

Lifecycle temporary files are created relative to the transaction's directory
descriptor.

Temporary creation uses:

- `O_CREAT`;
- `O_EXCL`;
- `O_NOFOLLOW` where available;
- `O_CLOEXEC` where available.

The temporary file is validated with `fstat`, written, flushed, and fsynced.

The final publication uses descriptor-relative `os.rename` with both
`src_dir_fd` and `dst_dir_fd` set to the same anchored directory.

This preserves atomic same-directory replacement while preventing a parent
pathname replacement from redirecting the final rename into another directory.

The anchored directory descriptor itself is fsynced where supported.

## Source-registry lifecycle state

Source-registry state now uses the same anchored transaction model.

During authoritative source-registry state mutation:

`lock -> reload -> CAS -> temporary write -> atomic rename`

all filesystem operations are performed relative to the same already-open
directory descriptor.

Standalone registry-state reads open a short-lived anchor.

## Parent-directory replacement behavior

Adversarial tests rename the original state directory after lock acquisition
and create a new directory at the original pathname.

The transaction continues to read/write through the directory descriptor that
was opened before the replacement.

The replacement directory remains untouched.

This behavior is covered for both:

- intelligence lifecycle state;
- source-registry lifecycle state.

## Temporary-file identity

Phase 34 also changes anchored state temporary-file creation from deterministic
`O_TRUNC` reopening to exclusive `O_CREAT | O_EXCL` creation.

A pre-existing temporary filesystem object therefore causes the write to fail
rather than being reused or truncated.

Temporary cleanup remains identity checked.

## Existing semantics retained

Phase 34 preserves:

- lifecycle-state locking;
- stale-lock recovery;
- lock timeout behavior;
- compare-and-swap concurrency checks;
- delegation history;
- persistent revocation history;
- generation rollback rejection;
- source-registry lifecycle semantics;
- file fsync before publication;
- atomic same-directory publication;
- directory fsync where supported.

## Security invariants

Phase 34 establishes:

1. Mutation transactions use one opened state-directory descriptor.
2. Lock creation is relative to that descriptor.
3. Existing lock inspection is relative to that descriptor.
4. Lock stat/unlink operations remain within that directory namespace.
5. Lifecycle-state reload during CAS uses the same directory descriptor.
6. Lifecycle temporary creation and publication use the same descriptor.
7. Source-registry state reload/write uses the same descriptor.
8. Parent-directory pathname replacement after lock acquisition does not
   redirect the transaction.
9. Temporary state files are created exclusively rather than truncating a
   pre-existing object.
10. Atomic publication remains same-directory.
11. Lifecycle/registry rollback semantics are unchanged.
12. This phase does not make persisted state cryptographically tamper-evident.

## Remaining limits

Phase 34 materially strengthens local filesystem identity but does not claim
complete resistance against a fully privileged hostile local actor.

Remaining considerations include:

- ancestor components above the opened state directory may themselves have
  been resolved before the directory descriptor was obtained;
- directory creation still necessarily begins from pathname resolution;
- a sufficiently privileged actor can manipulate mounts or filesystem
  namespaces below the process;
- platform behavior differs where POSIX `dir_fd`, `O_DIRECTORY`, or
  `O_NOFOLLOW` semantics are unavailable;
- lifecycle and registry state remain integrity-protected by storage
  discipline, not cryptographic authentication;
- direct external/operator replacement of valid regular state files remains a
  separate tamper-evidence concern.

A future phase could address cryptographic state authentication or stronger
root-directory anchoring if the threat model requires resistance to broader
local administrator-level manipulation.

## Result

Authoritative mutation now follows:

`open state directory -> retain dir fd -> acquire relative lock -> reload state
relative to same dir fd -> CAS -> exclusive relative temp create -> fsync ->
relative atomic rename -> directory fsync -> identity-checked relative unlock`

for both lifecycle and source-registry authority state.
