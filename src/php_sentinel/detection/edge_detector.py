from __future__ import annotations

from collections import defaultdict

import httpx

from php_sentinel.models.edge import (
    ApplicationReachability,
    EdgeAssessment,
    EdgeProvider,
    EdgeResponseClass,
    EdgeSignal,
)

_BODY_LIMIT = 200_000
_PROVIDER_MIN_SCORE = 0.50
_AMBIGUITY_MARGIN = 0.35

_EDGE_PROVIDERS = {
    EdgeProvider.CLOUDFLARE,
    EdgeProvider.AKAMAI,
    EdgeProvider.IMPERVA,
    EdgeProvider.FASTLY,
    EdgeProvider.BUNNYCDN,
    EdgeProvider.AWS_CLOUDFRONT,
    EdgeProvider.SUCURI,
    EdgeProvider.AZURE_EDGE,
    EdgeProvider.GENERIC_CDN,
}


def _add_signal(
    signals: list[EdgeSignal],
    *,
    signal_type: str,
    source: str,
    value: str,
    weight: float,
    provider: EdgeProvider | None = None,
) -> None:
    signals.append(
        EdgeSignal(
            signal_type=signal_type,
            source=source,
            value=value,
            weight=weight,
            provider=provider,
        )
    )


def _provider_scores(signals: list[EdgeSignal]) -> dict[EdgeProvider, float]:
    scores: dict[EdgeProvider, float] = defaultdict(float)

    for signal in signals:
        if signal.provider is not None:
            scores[signal.provider] += signal.weight

    return dict(scores)


def _provider_decision(
    signals: list[EdgeSignal],
) -> tuple[EdgeProvider, float, list[EdgeProvider], bool]:
    scores = _provider_scores(signals)

    ranked = sorted(
        (
            (provider, score)
            for provider, score in scores.items()
            if score >= _PROVIDER_MIN_SCORE
        ),
        key=lambda item: (-item[1], item[0].value),
    )

    if not ranked:
        return EdgeProvider.NONE, 0.0, [], False

    candidates = [provider for provider, _score in ranked]
    top_provider, top_score = ranked[0]

    if len(ranked) > 1:
        second_score = ranked[1][1]

        if top_score - second_score < _AMBIGUITY_MARGIN:
            return (
                EdgeProvider.UNKNOWN,
                min(1.0, top_score),
                candidates,
                True,
            )

    return (
        top_provider,
        min(1.0, top_score),
        candidates,
        False,
    )


def _application_specific_evidence(headers: dict[str, str]) -> bool:
    x_powered_by = headers.get("x-powered-by", "")

    return "php" in x_powered_by


def classify_edge_response(response: httpx.Response) -> EdgeAssessment:
    headers = {
        key.lower(): value.lower()
        for key, value in response.headers.items()
    }
    body = response.text[:_BODY_LIMIT].lower()
    status = response.status_code
    signals: list[EdgeSignal] = []

    server = headers.get("server", "")

    if "cloudflare" in server:
        _add_signal(
            signals,
            signal_type="server_header",
            source="header:server",
            value="cloudflare",
            weight=0.70,
            provider=EdgeProvider.CLOUDFLARE,
        )

    if "cf-ray" in headers:
        _add_signal(
            signals,
            signal_type="edge_request_id",
            source="header:cf-ray",
            value="present",
            weight=0.55,
            provider=EdgeProvider.CLOUDFLARE,
        )

    if "cf-cache-status" in headers:
        _add_signal(
            signals,
            signal_type="cache_header",
            source="header:cf-cache-status",
            value=headers["cf-cache-status"],
            weight=0.35,
            provider=EdgeProvider.CLOUDFLARE,
        )

    if headers.get("cf-mitigated") == "challenge":
        _add_signal(
            signals,
            signal_type="challenge_header",
            source="header:cf-mitigated",
            value="challenge",
            weight=0.90,
            provider=EdgeProvider.CLOUDFLARE,
        )

    if "akamaighost" in server:
        _add_signal(
            signals,
            signal_type="server_header",
            source="header:server",
            value="akamaighost",
            weight=0.80,
            provider=EdgeProvider.AKAMAI,
        )

    if "x-akamai-transformed" in headers:
        _add_signal(
            signals,
            signal_type="transform_header",
            source="header:x-akamai-transformed",
            value="present",
            weight=0.65,
            provider=EdgeProvider.AKAMAI,
        )

    if "akamai-grn" in headers:
        _add_signal(
            signals,
            signal_type="edge_request_id",
            source="header:akamai-grn",
            value="present",
            weight=0.70,
            provider=EdgeProvider.AKAMAI,
        )

    if "x-iinfo" in headers:
        _add_signal(
            signals,
            signal_type="edge_diagnostic_header",
            source="header:x-iinfo",
            value="present",
            weight=0.80,
            provider=EdgeProvider.IMPERVA,
        )

    if "imperva" in headers.get("x-cdn", ""):
        _add_signal(
            signals,
            signal_type="cdn_header",
            source="header:x-cdn",
            value="imperva",
            weight=0.80,
            provider=EdgeProvider.IMPERVA,
        )

    if "fastly" in headers.get("x-served-by", ""):
        _add_signal(
            signals,
            signal_type="edge_node_header",
            source="header:x-served-by",
            value="fastly",
            weight=0.70,
            provider=EdgeProvider.FASTLY,
        )

    if "fastly" in headers.get("via", ""):
        _add_signal(
            signals,
            signal_type="via_header",
            source="header:via",
            value="fastly",
            weight=0.55,
            provider=EdgeProvider.FASTLY,
        )

    if "bunnycdn" in server or "bunnycdn" in headers.get("cdn-server", ""):
        _add_signal(
            signals,
            signal_type="cdn_server_header",
            source="header:server",
            value="bunnycdn",
            weight=0.80,
            provider=EdgeProvider.BUNNYCDN,
        )

    if "x-amz-cf-id" in headers:
        _add_signal(
            signals,
            signal_type="edge_request_id",
            source="header:x-amz-cf-id",
            value="present",
            weight=0.65,
            provider=EdgeProvider.AWS_CLOUDFRONT,
        )

    if "x-amz-cf-pop" in headers:
        _add_signal(
            signals,
            signal_type="edge_pop_header",
            source="header:x-amz-cf-pop",
            value="present",
            weight=0.60,
            provider=EdgeProvider.AWS_CLOUDFRONT,
        )

    if "cloudfront" in headers.get("via", ""):
        _add_signal(
            signals,
            signal_type="via_header",
            source="header:via",
            value="cloudfront",
            weight=0.55,
            provider=EdgeProvider.AWS_CLOUDFRONT,
        )

    if "sucuri" in server:
        _add_signal(
            signals,
            signal_type="server_header",
            source="header:server",
            value="sucuri",
            weight=0.75,
            provider=EdgeProvider.SUCURI,
        )

    if "x-sucuri-id" in headers:
        _add_signal(
            signals,
            signal_type="edge_request_id",
            source="header:x-sucuri-id",
            value="present",
            weight=0.75,
            provider=EdgeProvider.SUCURI,
        )

    if "x-sucuri-cache" in headers:
        _add_signal(
            signals,
            signal_type="cache_header",
            source="header:x-sucuri-cache",
            value=headers["x-sucuri-cache"],
            weight=0.55,
            provider=EdgeProvider.SUCURI,
        )

    if "x-azure-ref" in headers:
        _add_signal(
            signals,
            signal_type="edge_request_id",
            source="header:x-azure-ref",
            value="present",
            weight=0.65,
            provider=EdgeProvider.AZURE_EDGE,
        )

    if "mod_security" in body or "modsecurity" in body:
        _add_signal(
            signals,
            signal_type="waf_body_marker",
            source="body",
            value="modsecurity",
            weight=0.80,
            provider=EdgeProvider.MODSECURITY,
        )

    if "incapsula incident id" in body:
        _add_signal(
            signals,
            signal_type="waf_body_marker",
            source="body",
            value="incapsula incident id",
            weight=0.75,
            provider=EdgeProvider.IMPERVA,
        )

    sucuri_block = (
        "access denied - sucuri website firewall" in body
        or "sucuri website firewall - access denied" in body
    )

    if sucuri_block:
        _add_signal(
            signals,
            signal_type="waf_body_marker",
            source="body",
            value="sucuri website firewall access denied",
            weight=0.85,
            provider=EdgeProvider.SUCURI,
        )

    provider, confidence, candidates, ambiguous = _provider_decision(signals)

    edge_detected = (
        provider in _EDGE_PROVIDERS
        or (
            provider == EdgeProvider.UNKNOWN
            and any(candidate in _EDGE_PROVIDERS for candidate in candidates)
        )
    )

    cloudflare_candidate = (
        provider == EdgeProvider.CLOUDFLARE
        or EdgeProvider.CLOUDFLARE in candidates
    )

    cloudflare_challenge = (
        headers.get("cf-mitigated") == "challenge"
        or (
            cloudflare_candidate
            and (
                "just a moment" in body
                or "challenge-platform" in body
                or "__cf_chl_" in body
            )
        )
    )

    if cloudflare_challenge:
        return EdgeAssessment(
            edge_detected=True,
            waf_detected=True,
            provider=provider,
            provider_confidence=confidence,
            provider_ambiguous=ambiguous,
            provider_candidates=candidates,
            response_class=EdgeResponseClass.BOT_CHALLENGE,
            application_reachability=ApplicationReachability.NOT_REACHED,
            challenge_detected=True,
            signals=signals,
            rationale=[
                "The response contains explicit edge challenge evidence.",
                (
                    "Challenge responses cannot establish PHP runtime or "
                    "application vulnerability state."
                ),
            ],
        )

    waf_block_marker = (
        "incapsula incident id" in body
        or "mod_security" in body
        or "modsecurity" in body
        or sucuri_block
    )

    if status in {403, 406} and waf_block_marker:
        if provider == EdgeProvider.NONE:
            provider = EdgeProvider.GENERIC_WAF
            confidence = max(confidence, 0.55)
            candidates = [EdgeProvider.GENERIC_WAF]

        return EdgeAssessment(
            edge_detected=edge_detected,
            waf_detected=True,
            provider=provider,
            provider_confidence=confidence,
            provider_ambiguous=ambiguous,
            provider_candidates=candidates,
            response_class=EdgeResponseClass.WAF_BLOCK,
            application_reachability=ApplicationReachability.NOT_REACHED,
            signals=signals,
            rationale=[
                "The response combines a denial status with WAF-specific evidence.",
                (
                    "The denied response is not sufficient evidence that the "
                    "request reached application execution."
                ),
            ],
        )

    if status == 429:
        return EdgeAssessment(
            edge_detected=edge_detected,
            provider=provider,
            provider_confidence=confidence,
            provider_ambiguous=ambiguous,
            provider_candidates=candidates,
            response_class=EdgeResponseClass.RATE_LIMIT,
            application_reachability=ApplicationReachability.UNKNOWN,
            rate_limited=True,
            signals=signals,
            rationale=[
                "HTTP 429 indicates an active rate-limiting decision.",
                (
                    "The limiting layer cannot be assumed to be the "
                    "application without additional evidence."
                ),
            ],
        )

    if edge_detected and status in {502, 503, 504}:
        return EdgeAssessment(
            edge_detected=True,
            provider=provider,
            provider_confidence=confidence,
            provider_ambiguous=ambiguous,
            provider_candidates=candidates,
            response_class=EdgeResponseClass.ORIGIN_FAILURE,
            application_reachability=ApplicationReachability.NOT_REACHED,
            signals=signals,
            rationale=[
                (
                    "A recognized edge provider returned an upstream/origin "
                    "failure status."
                ),
                "Application runtime evidence is not established by this response.",
            ],
        )

    if edge_detected:
        if _application_specific_evidence(headers):
            response_class = EdgeResponseClass.APPLICATION_RESPONSE
            reachability = ApplicationReachability.PROBABLE
            rationale = [
                (
                    "The response traversed a recognized edge/CDN layer and "
                    "also contains application-specific PHP evidence."
                ),
                (
                    "Application reachability remains probable rather than "
                    "confirmed because the response traversed an intermediary."
                ),
            ]
        else:
            response_class = EdgeResponseClass.EDGE_RESPONSE
            reachability = ApplicationReachability.UNKNOWN
            rationale = [
                "The response contains recognized edge/CDN evidence.",
                (
                    "No independent application-specific PHP evidence was "
                    "observed in the response."
                ),
            ]

        if ambiguous:
            rationale.insert(
                0,
                "Conflicting provider evidence prevents authoritative attribution.",
            )

        return EdgeAssessment(
            edge_detected=True,
            provider=provider,
            provider_confidence=confidence,
            provider_ambiguous=ambiguous,
            provider_candidates=candidates,
            response_class=response_class,
            application_reachability=reachability,
            signals=signals,
            rationale=rationale,
        )

    if provider in {
        EdgeProvider.MODSECURITY,
        EdgeProvider.GENERIC_WAF,
    }:
        return EdgeAssessment(
            edge_detected=False,
            waf_detected=True,
            provider=provider,
            provider_confidence=confidence,
            provider_ambiguous=ambiguous,
            provider_candidates=candidates,
            response_class=EdgeResponseClass.EDGE_RESPONSE,
            application_reachability=ApplicationReachability.UNKNOWN,
            signals=signals,
            rationale=[
                "WAF-related evidence was observed without a recognized CDN edge.",
                "Application reachability requires additional evidence.",
            ],
        )

    return EdgeAssessment(
        edge_detected=False,
        waf_detected=False,
        provider=EdgeProvider.NONE,
        provider_confidence=0.0,
        provider_ambiguous=False,
        provider_candidates=[],
        response_class=EdgeResponseClass.APPLICATION_RESPONSE,
        application_reachability=ApplicationReachability.PROBABLE,
        signals=signals,
        rationale=[
            "No supported edge or WAF fingerprint was established.",
            (
                "Absence of an edge fingerprint does not by itself prove "
                "direct origin communication."
            ),
        ],
    )
