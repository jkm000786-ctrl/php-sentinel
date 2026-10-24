# Phase 41 — Cross-Platform Security Semantics

## Purpose

Phase 41 defines which filesystem hardening guarantees are mandatory for
security-sensitive PHP Sentinel operations and which guarantees are only
best-effort portability enhancements.

Earlier storage and cache phases relied heavily on POSIX descriptor semantics.
On Linux and WSL those primitives are available, but silently substituting
weaker behavior on another operating system would make the resulting security
properties ambiguous.

The Phase 41 rule is therefore explicit:

> A security-sensitive operation must fail closed when the platform cannot
> provide a filesystem primitive required to preserve its trust boundary.

Optional hardening properties may degrade only where that degradation does not
change the trust or authorization decision.

---

## Central capability model

Filesystem capability detection is centralized in:

`php_sentinel.intelligence.platform_security`

The model currently records whether the runtime supports:

- `O_NOFOLLOW`,
- `O_DIRECTORY`,
- descriptor-relative `open`,
- descriptor-relative `mkdir`,
- descriptor-relative `stat`,
- descriptor-relative `unlink`,
- descriptor-relative `rename`,
- `stat(..., follow_symlinks=False)`.

The capability detector exists only to determine what the current platform can
actually enforce. It is not itself a fallback mechanism.

---

## Mandatory no-follow semantics

Local files that form security-sensitive inputs must not silently lose
no-follow behavior.

Standalone readers include:

- external intelligence policy and manifest files,
- trust-store files,
- staged intelligence artifacts,
- comparison reports.

Before opening these files, PHP Sentinel requires `O_NOFOLLOW`.

If the platform does not expose that primitive, the operation is denied rather
than reopening the file without equivalent protection.

This prevents a platform difference from silently changing:

`trusted pathname -> no-follow file object`

into:

`trusted pathname -> potentially followed symbolic link`.

---

## Anchored authority-state storage

Authority-state persistence requires a stronger capability set because the
storage model depends on descriptor-relative traversal.

The anchored directory contract requires:

- `O_NOFOLLOW`,
- `O_DIRECTORY`,
- `open(..., dir_fd=...)`,
- `mkdir(..., dir_fd=...)`,
- `stat(..., dir_fd=...)`,
- `unlink(..., dir_fd=...)`,
- `rename(..., src_dir_fd=..., dst_dir_fd=...)`,
- `stat(..., follow_symlinks=False)`.

This contract protects:

- lifecycle state,
- lifecycle lock objects,
- source-registry state,
- authority-state key storage,
- temporary authority-state objects,
- atomic descriptor-relative publication.

If those semantics are unavailable, `open_directory_anchor()` fails closed.

Authority-state callers translate that failure into their existing typed
storage-domain errors.

There is no pathname-only security downgrade.

---

## Verified-cache descriptor contract

Verified-cache inspection does not use the authority-state path-anchor walker,
so it has its own narrower capability contract.

Verified-cache descriptor access requires:

- `O_NOFOLLOW`,
- `O_DIRECTORY`,
- descriptor-relative `open`.

This is sufficient for the current cache inspection model:

1. reject a symbolic-link cache directory;
2. resolve and open the directory as a real directory;
3. retain the open directory descriptor;
4. open policy, manifest, and verification metadata relative to that
   descriptor;
5. reject symbolic-link or non-regular artifacts;
6. consume only bounded bytes from those opened descriptors.

If those capabilities are unavailable, cache inspection and activation fail
closed before artifact trust evaluation.

---

## Security flags are no longer silently optional

Security-sensitive code must not use patterns such as:

`getattr(os, "O_NOFOLLOW", 0)`

or:

`getattr(os, "O_DIRECTORY", 0)`

to continue execution after the required primitive disappears.

After Phase 41, such zero-value probing is confined to the central capability
detector, where it is used only to determine whether an operation may proceed.

Once the capability gate has passed, implementation paths use the actual
security flag directly.

`O_CLOEXEC` remains optional because loss of close-on-exec does not replace the
no-follow or descriptor-containment trust decision in the current process
model.

---

## POSIX mode tightening

Owner-only file and directory modes remain important defense in depth.

PHP Sentinel requests:

- state directories: `0700`,
- lifecycle state files: `0600`,
- registry state files: `0600`,
- authority key files: `0600`.

However, not every supported filesystem or operating system implements POSIX
mode bits with equivalent meaning.

Therefore `fchmod()` remains best effort after the secure descriptor has
already been obtained.

A failure to tighten mode bits does not cause PHP Sentinel to reinterpret a
symbolic link as safe or bypass any descriptor-containment check.

Tests explicitly establish that:

- secure anchored traversal remains usable when `fchmod()` is unsupported;
- authority-key creation and loading remain structurally safe;
- POSIX permission enforcement tests run only where those semantics are
  meaningful.

The resulting guarantee is:

> permission tightening is enforced where supported, but PHP Sentinel does not
> claim portable equivalence to POSIX ownership/mode semantics.

---

## File fsync versus directory fsync

Phase 41 also distinguishes write durability guarantees.

### File fsync

For authoritative lifecycle, registry, and authority-key persistence, syncing
the written file descriptor remains part of the write operation.

A failure of the required file write or file `fsync()` continues to fail the
persistence operation.

PHP Sentinel does not report such a write as successfully durable.

### Directory fsync

Directory `fsync()` support varies by operating system and filesystem.

The containing directory is therefore synchronized where supported after
publication, but directory-sync failure remains best effort.

Tests explicitly cover that lifecycle state, source-registry state, and the
authority key remain readable after a simulated unsupported directory
`fsync()`.

This does not mean all platforms have identical crash-consistency guarantees.

The precise guarantee is:

> PHP Sentinel requires successful file persistence before publication and
> requests containing-directory durability where the platform supports it.

---

## Windows and other non-POSIX platforms

Phase 41 does not claim that Windows exposes POSIX-equivalent filesystem
security primitives.

Instead, PHP Sentinel now evaluates the concrete Python runtime capabilities
needed by each security-sensitive operation.

If the Windows Python/runtime/filesystem combination cannot provide the
required no-follow or descriptor-relative semantics, the affected operation
fails closed.

This is preferable to silently running with a weaker pathname-based security
model.

A future native Windows implementation may provide equivalent security using
Windows-specific APIs, but equivalence must be demonstrated explicitly rather
than inferred from API naming.

---

## Capability scopes

Three distinct capability scopes are intentionally modeled.

### Standalone no-follow read

Used for files that need a safe final-component open but do not require
descriptor-relative traversal.

Required:

- `O_NOFOLLOW`.

### Verified-cache descriptor access

Used for verified-cache directory and artifact inspection.

Required:

- `O_NOFOLLOW`,
- `O_DIRECTORY`,
- descriptor-relative `open`.

### Anchored authority-state traversal

Used for mutable local authority state.

Required:

- `O_NOFOLLOW`,
- `O_DIRECTORY`,
- descriptor-relative `open`,
- descriptor-relative `mkdir`,
- descriptor-relative `stat`,
- descriptor-relative `unlink`,
- descriptor-relative `rename`,
- no-follow `stat`.

These scopes prevent an unnecessarily broad platform restriction while keeping
each trust boundary explicit.

---

## Security invariants

1. Missing `O_NOFOLLOW` must never silently become an ordinary pathname open
   for security-sensitive runtime input.

2. Missing `O_DIRECTORY` must never silently weaken a directory identity check
   where directory-descriptor semantics are required.

3. Authority-state operations fail closed when descriptor-relative traversal
   cannot be enforced.

4. Verified-cache inspection fails closed when its descriptor-security
   capability set is unavailable.

5. Capability probing occurs before a security-sensitive open is attempted.

6. Security flag probing with a zero fallback is confined to the central
   capability detector.

7. Once a capability gate succeeds, mandatory flags are used explicitly.

8. `fchmod()` is defense in depth and may be best effort on filesystems that do
   not implement portable POSIX mode semantics.

9. Best-effort mode tightening must never replace no-follow or regular-file
   validation.

10. File `fsync()` failures in authoritative persistence remain fatal.

11. Directory `fsync()` is requested where supported but does not imply
    identical crash consistency on every operating system or filesystem.

12. Cross-platform support means explicit capability evaluation, not silent
    emulation of unavailable security primitives.

13. No Phase 41 behavior creates a weaker fallback path merely to preserve
    feature availability.

14. Failure to satisfy a mandatory filesystem capability must occur before the
    resulting file object is accepted as trusted authority input.

---

## Non-goals

Phase 41 does not provide:

- Windows ACL management;
- Windows reparse-point handling through native Win32 APIs;
- filesystem sandboxing;
- mount-namespace protection;
- protection against a privileged kernel or administrator;
- process isolation;
- mandatory access control policy;
- identical crash-consistency guarantees across filesystems;
- portable equivalence of POSIX permission bits.

Those require separate platform-specific designs if they become product
requirements.

---

## Result

After Phase 41, PHP Sentinel no longer treats missing POSIX-style security
flags as harmless optional behavior.

The final model is:

`detect platform capability`

-> `require the capability appropriate to the trust boundary`

-> `fail closed if unavailable`

-> `perform descriptor/no-follow validation`

-> `apply portable best-effort hardening such as mode tightening or directory
durability sync`

This makes cross-platform differences explicit without weakening the
evidence-driven intelligence trust model.
