# Phase 20 — Intelligence Source Registry & Multi-Channel Policy

Phase 20 adds an operator-controlled source registry above the existing
intelligence update channel.

The registry does not replace signature trust or lifecycle authority.

## Separation of identities

PHP Sentinel treats these as separate concepts:

- source ID,
- channel,
- signer ID,
- policy ID.

A source being configured does not make its content trusted.

A signer being globally trusted does not automatically authorize that
signer for every source.

## Source registry

Each source defines:

- unique source ID,
- enabled/disabled state,
- HTTPS base URL,
- allowed signer IDs,
- one or more named channels.

Each channel defines:

- channel name,
- enabled/disabled state,
- relative policy path,
- relative manifest path,
- minimum accepted generation.

## URL confinement

Registry base URLs must use HTTPS.

Credentials, query strings, and fragments are prohibited.

Channel paths must be relative and cannot contain dot or parent
segments.

Resolved policy and manifest URLs must remain below the configured
source base URL.

## Signer narrowing

The local trust store remains the cryptographic authority.

The source registry can only narrow that trust.

A manifest must first pass normal trust-store verification.

After that, its signer must also appear in the source's
`allowed_signer_ids`.

This means a source registry can reject a globally trusted signer but
cannot make an unknown signer trusted.

## Generation policy

Effective minimum generation is:

`max(operator minimum, source-channel minimum)`

A source therefore cannot weaken the operator's lifecycle policy.

## Source/channel provenance

Registry-aware staging records source ID and channel in staging
metadata.

That provenance is carried into verification metadata and the verified
cache.

This provenance is descriptive routing context, not cryptographic
publisher identity.

Signature verification remains tied to the manifest signer and local
trust store.

## Disabled sources and channels

Disabled sources and disabled channels fail closed before network
retrieval or activation.

## Cache isolation

Registry-aware cache selection requires explicit source and channel.

A cached item from another source/channel is not silently substituted.

Existing cache conflict detection remains active.

## Activation authority

Registry-aware cache activation still delegates to the existing
authoritative activation boundary.

Activation re-reads:

- policy,
- manifest,
- current trust store,
- current lifecycle state.

The registry then additionally requires the current verified signer to
remain authorized for the selected source.

## Security interpretation

The registry controls where PHP Sentinel may obtain intelligence and
which already-trusted signers are acceptable for each source.

It does not:

- create signer trust,
- prove a vulnerability,
- authorize target testing,
- permit exploit execution,
- let one source silently override another source.
