# Edge-Aware Authoritative Assessment

Phase 59 moves passive edge intelligence into the canonical assessment
authority path.

## Authority boundary

Every unified HTTP response is classified by the edge intelligence layer before
PHP runtime, version, SAPI, CVE, or finding conclusions are accepted.

When the response is an edge response, WAF block, bot challenge, rate limit, or
recognized origin failure with application reachability `unknown` or
`not_reached`, PHP Sentinel suppresses application interpretation.

The resulting canonical state is:

- top-level assessment: `inconclusive`
- PHP detected: `false`
- PHP version: unknown
- exposure priority: `unknown`
- applicable CVE set: empty
- per-CVE decisions: `inconclusive`
- findings: `inconclusive`

This prevents edge-generated content or headers from creating application
exposure conclusions.

## Permitted application evidence

A response classified as `application_response` may continue through the
existing PHP/CVE pipeline. For an edge-mediated response this currently
requires independent application-specific PHP evidence and results in
`probable`, not `confirmed`, application reachability.

## Provenance

Edge assessment is included in the canonical evidence payload and target
identity material. Provenance explicitly records:

- edge detected
- WAF detected
- provider and provider confidence
- provider ambiguity
- response class
- application reachability
- challenge state
- rate-limit state

## Cross-layer consistency

The consistency validator fails closed if edge-gated evidence coexists with a
non-inconclusive assessment, non-inconclusive CVE decision, or
non-inconclusive finding.

No public-target WAF bypass, challenge solving, CAPTCHA solving, origin
discovery, or evasive request mutation is introduced by this integration.
