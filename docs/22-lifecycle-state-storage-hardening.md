# Phase 17 — Lifecycle State Storage Hardening

Phase 17 hardens the local persistent state used for intelligence
rollback and replay protection.

## Threats addressed

The lifecycle store is security-sensitive because it records the
highest intelligence generation previously accepted.

Weak persistence could permit:

- lost updates between concurrent processes,
- accidental rollback after a race,
- malformed state being treated as empty state,
- overly broad filesystem permissions,
- partially durable writes after a crash,
- unsupported future state schemas being accepted silently.

## Secure state permissions

Where POSIX permission semantics are available, PHP Sentinel attempts
to enforce:

- lifecycle-state directory: `0700`
- lifecycle-state file: `0600`
- lifecycle lock file: `0600`

On filesystems that do not implement POSIX permission bits, these mode
changes are best-effort. Actual read/write failures still fail closed.

## Atomic and durable persistence

The state payload is written to a same-directory temporary file.

Before activation state is replaced:

1. the temporary file is written,
2. its buffers are flushed,
3. the file is `fsync`'d,
4. `os.replace()` atomically replaces the destination,
5. the destination directory is `fsync`'d where supported.

The temporary file is removed on failed writes.

## Concurrency control

Lifecycle state updates use an exclusive lock file.

The lock uses atomic `O_CREAT | O_EXCL` creation.

Acquisition is bounded. A process does not wait forever for another
writer.

Old locks are recovered only after the stale threshold and only when
the recorded owner process is no longer alive.

## Evaluation-to-commit race protection

External intelligence activation loads a lifecycle-state snapshot
before evaluation.

When the accepted result is persisted, the current state is compared
with that snapshot while holding the write lock.

If another process changed the lifecycle state after evaluation,
persistence fails closed and activation must be retried.

This prevents a stale evaluation from silently overwriting a newer
rollback-protection state.

## Store schema version

Lifecycle state currently supports:

`store_version = 1`

Unknown versions fail closed.

## Corruption handling

Malformed JSON, invalid state models, and unsupported state versions
raise a lifecycle storage error.

Corrupted rollback state is never silently interpreted as an empty
state.

## Integrity boundary

This phase improves local filesystem safety, concurrency behavior, and
durability.

It does **not** make the lifecycle-state file cryptographically
tamper-evident.

Adding an HMAC or signature would require a separate protected local
key-management design. PHP Sentinel does not invent or embed a secret
key merely to claim state authenticity.
