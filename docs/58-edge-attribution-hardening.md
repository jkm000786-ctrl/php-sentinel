# Edge Attribution Hardening

Phase 58 strengthens PHP Sentinels passive edge intelligence before it becomes
an authoritative input to the unified assessment pipeline.

## Attribution rules

Provider attribution is evidence-weighted and explicitly ambiguity-aware.
When multiple providers have similarly strong evidence, PHP Sentinel reports
the provider as `unknown`, preserves the candidate set, and does not pretend a
single provider has been established.

Opaque edge request identifiers are represented only as `present`; raw request
IDs are not retained in edge signal evidence.

## False-positive controls

Generic HTTP denial text is not sufficient to establish a WAF.

In particular:

- generic HTTP 403 is not a WAF finding;
- generic `request rejected` text is not a WAF finding;
- CloudFront evidence does not establish AWS WAF;
- Sucuri edge evidence does not establish a Sucuri WAF block unless explicit
  Sucuri firewall block evidence is also present;
- an edge response without independent PHP evidence remains an `edge_response`
  with unknown application reachability.

## Provider expansion

Passive conservative fingerprints now include:

- Cloudflare
- Akamai
- Imperva / Incapsula
- Fastly
- BunnyCDN
- AWS CloudFront
- Sucuri
- Azure edge infrastructure
- ModSecurity
- generic CDN / WAF classifications

## Application evidence

A recognized edge/CDN response is promoted to `application_response` only when
independent application-specific PHP evidence is visible. Even then,
reachability is only `probable`, never `confirmed`.

No public-target WAF bypass, anti-bot bypass, CAPTCHA solving, origin discovery,
or evasive request mutation is part of this subsystem.
