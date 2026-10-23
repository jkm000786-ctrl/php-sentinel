# Phase 24 — Registry-Enforced Trusted Update Transport

Phase 24 hardens the remote intelligence update path around the existing
signature, lifecycle, verified-cache, and source-registry trust model.

The core rule remains:

`transport success != intelligence trust`

Transport controls constrain where bytes may come from and how they are
retrieved. They do not replace manifest signature verification, local trust
stores, lifecycle policy, source/channel authorization, or activation-time
reverification.

## Trust boundary

Authenticated remote source workflows use the signed source-registry boundary.

The workflow is:

`verify signed registry -> select authorized source/channel -> transport -> untrusted staging -> intelligence verification -> verified cache -> activation`

The signed registry is authenticated before remote staging begins.

The exact in-memory registry object produced by signed-registry verification is
used for source/channel selection. The workflow does not authenticate a
registry and then re-read an unauthenticated raw registry file before network
egress.

Raw registry APIs remain available as explicit operator-local configuration
primitives. They do not claim publisher authentication.

The source registry can narrow existing trust. It cannot create signer trust or
expand the local intelligence trust store.

Registry trust and intelligence-policy trust remain separate trust domains.

## CLI enforcement

Remote source-oriented CLI workflows use the signed-registry boundary for:

- source staging;
- staged-bundle verification;
- verified-cache activation.

The CLI does not use the raw registry staging, verification, or activation APIs
for authenticated remote workflows.

## Structural URL authority

Source/channel URLs are resolved from the configured registry base URL and then
checked structurally.

Containment requires:

- matching URL scheme;
- matching normalized hostname;
- matching effective port;
- no embedded credentials;
- no query string;
- no fragment;
- candidate path beneath the configured base path.

This replaces string-prefix authority checks.

A hostname such as:

`updates.example.test.evil`

does not satisfy a base authority of:

`updates.example.test`

Likewise, a sibling path or a different explicit port is not accepted merely
because its textual representation shares a prefix.

## HTTPS requirement

Remote intelligence update URLs must use HTTPS.

URLs are rejected when they:

- use a non-HTTPS scheme;
- omit a hostname;
- contain embedded credentials;
- contain a fragment.

Transport encryption is necessary but is not treated as intelligence
authenticity.

## Environment isolation

The internally created HTTPX client uses:

`trust_env=False`

PHP Sentinel therefore does not implicitly inherit environment-configured HTTP
or HTTPS proxies for the default intelligence-update transport.

An explicitly injected client remains an operator/test dependency boundary.

## Redirect policy

Redirects are refused.

The default client is configured with:

`follow_redirects=False`

and each update request also explicitly sets:

`follow_redirects=False`.

A redirect response is rejected instead of being followed to a new authority.

This prevents a validated registry URL from silently expanding its transport
authority through HTTP redirects.

## Preflight destination containment

Before any update request is sent, PHP Sentinel resolves each remote hostname.

Every resolved address must satisfy the update-destination policy.

The policy rejects non-public destinations including:

- loopback;
- private;
- link-local;
- multicast;
- unspecified;
- reserved;
- other non-global addresses.

Mixed DNS answers fail closed.

If a hostname resolves to both an allowed public address and a blocked address,
the update is rejected before fetch.

Literal IP update URLs are subject to the same address policy.

DNS preflight by itself is not treated as proof of the address ultimately used
by the TCP connection.

## Connected-peer verification

Phase 24 therefore adds a second network boundary after connection
establishment.

For normal HTTPX/HTTPCore responses, PHP Sentinel obtains the underlying
`network_stream` and reads its actual `server_addr`.

Before response-body bytes are accepted:

1. the connected peer address is normalized as an IP address;
2. the peer must still satisfy the public update-destination policy;
3. the peer must be present in the exact address set obtained during preflight
   resolution for that URL.

If the transport does not expose usable peer information, the normal
verification path fails closed.

If the connected peer is outside the prevalidated address set, the update is
rejected before its response body is consumed.

## DNS-rebinding boundary

The combination of:

- preflight DNS validation; and
- post-connect actual-peer membership verification

materially mitigates DNS-rebinding attacks on the normal HTTPX/HTTPCore update
path.

This implementation performs peer verification rather than socket-address
pinning.

PHP Sentinel therefore does not claim that DNS resolution is cryptographically
bound to connection establishment, nor that the transport layer itself pins a
specific pre-resolved address.

Its enforced property is narrower and explicit:

> the actual connected peer must belong to the previously validated public
> address set before update response bytes are accepted.

Test-only or explicitly injected peer-address providers are dependency seams
and are not evidence that an arbitrary supplied transport has the same
socket-level guarantees as the default HTTPX/HTTPCore path.

## Response-size limits

Update objects are streamed with a configured maximum byte count.

If the accumulated response exceeds that limit, staging fails.

Empty update objects are also rejected.

Transport size limits are availability and resource-consumption controls. They
do not establish authenticity or policy correctness.

## Timeout boundary

The default update client uses the configured HTTPX timeout value.

Timeouts constrain network operations but do not affect signer trust,
source-registry authority, or lifecycle acceptance.

## Staging semantics

Successful download writes into untrusted staging.

Staging records transport metadata including object hashes and sizes.

Raw transport SHA-256 values provide integrity/equivalence evidence for the
downloaded bytes. They do not prove publisher identity.

Staging does not advance intelligence lifecycle state.

Signed-registry staging verification is also read-only with respect to registry
lifecycle state.

## Verification and promotion

After staging, intelligence verification still requires the existing
authoritative controls:

- policy parsing;
- manifest parsing;
- manifest hash binding;
- configured intelligence trust store;
- signature verification;
- signer authorization;
- lifecycle evaluation;
- source/channel signer restrictions;
- source/channel minimum generation.

Only verified candidates may enter the verified cache.

Transport acceptance cannot promote unverified bytes.

## Activation

Activation remains an authoritative mutation boundary.

Activation re-evaluates current authority rather than trusting stale staging or
cache metadata.

The activation path uses:

- the currently authenticated registry;
- the current source/channel policy;
- the current local intelligence trust store;
- the current intelligence lifecycle state;
- the selected verified-cache candidate.

Current authority can therefore reject a candidate that was valid at an
earlier staging or verification time.

## Failure behavior

Phase 24 fails closed for transport-policy violations.

Examples include:

- signed-registry authentication failure;
- disabled or unauthorized source/channel;
- URL authority escape;
- non-HTTPS update URL;
- embedded URL credentials;
- redirect response;
- DNS resolution failure;
- empty DNS result;
- any blocked resolved address;
- malformed resolver address;
- missing connected-peer information;
- connected peer outside the prevalidated set;
- connected peer that is not public;
- oversized response;
- empty response;
- transport failure.

A failure does not make remote bytes trusted and does not bypass subsequent
cryptographic or lifecycle verification.

## Security invariants

Phase 24 establishes these invariants:

1. Authenticated remote source workflows verify the signed registry before
   network egress.
2. Source/channel selection consumes the exact authenticated in-memory registry
   capability.
3. Registry authorization narrows trust and never creates signer trust.
4. Update URLs must use HTTPS.
5. Default HTTP transport ignores environment proxy configuration.
6. Redirects are refused at both client and per-request boundaries.
7. Every preflight DNS answer must be a globally routable public unicast
   destination.
8. Mixed public/private DNS answers fail closed.
9. The actual connected peer must belong to the exact prevalidated address set
   before response bytes are accepted.
10. Source URL containment is structural rather than string-prefix based.
11. Transport success does not establish intelligence authenticity.
12. Staging does not advance lifecycle authority.
13. Verified-cache promotion requires existing intelligence verification.
14. Activation re-verifies current registry, trust, signer, policy, and
    lifecycle authority.

## Non-goals

Phase 24 does not:

- make transport equivalent to cryptographic publisher trust;
- allow a source registry to add trusted signer keys;
- replace the local intelligence trust store;
- replace intelligence lifecycle rollback protection;
- persist trust based only on a successful HTTP request;
- follow redirects to discover alternate update locations;
- permit private or loopback update destinations;
- claim socket-address pinning;
- claim that an injected arbitrary HTTP client provides the same peer
  observability as the default HTTPX/HTTPCore transport;
- turn staged or cached metadata into an authority token.

## Result

Phase 24 makes the trusted intelligence update path registry-enforced and
network-constrained while preserving the existing separation between:

- transport;
- registry authority;
- cryptographic signer trust;
- lifecycle authorization;
- verified cache state; and
- activation authority.

The transport is now substantially more resistant to SSRF-style destination
abuse, redirect-based authority expansion, environment proxy inheritance, and
DNS rebinding, without overstating those controls as publisher authenticity.
