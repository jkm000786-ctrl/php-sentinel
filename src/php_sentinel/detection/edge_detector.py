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
) -> tuple[EdgeProvider, float]:
    scores = _provider_scores(signals)

    if not scores:
        return EdgeProvider.NONE, 0.0

    provider, score = max(
        scores.items(),
        key=lambda item: item[1],
    )

    return provider, min(1.0, score)


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
            value=server,
            weight=0.70,
            provider=EdgeProvider.CLOUDFLARE,
        )

    if "cf-ray" in headers:
        _add_signal(
            signals,
            signal_type="edge_request_id",
            source="header:cf-ray",
            value=headers["cf-ray"],
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
            value=server,
            weight=0.80,
            provider=EdgeProvider.AKAMAI,
        )

    if "x-akamai-transformed" in headers:
        _add_signal(
            signals,
            signal_type="transform_header",
            source="header:x-akamai-transformed",
            value=headers["x-akamai-transformed"],
            weight=0.65,
            provider=EdgeProvider.AKAMAI,
        )

    if "akamai-grn" in headers:
        _add_signal(
            signals,
            signal_type="edge_request_id",
            source="header:akamai-grn",
            value=headers["akamai-grn"],
            weight=0.70,
            provider=EdgeProvider.AKAMAI,
        )

    if "x-iinfo" in headers:
        _add_signal(
            signals,
            signal_type="edge_diagnostic_header",
            source="header:x-iinfo",
            value=headers["x-iinfo"],
            weight=0.80,
            provider=EdgeProvider.IMPERVA,
        )

    if "imperva" in headers.get("x-cdn", ""):
        _add_signal(
            signals,
            signal_type="cdn_header",
            source="header:x-cdn",
            value=headers["x-cdn"],
            weight=0.80,
            provider=EdgeProvider.IMPERVA,
        )

    if "fastly" in headers.get("x-served-by", ""):
        _add_signal(
            signals,
            signal_type="edge_node_header",
            source="header:x-served-by",
            value=headers["x-served-by"],
            weight=0.70,
            provider=EdgeProvider.FASTLY,
        )

    if "fastly" in headers.get("via", ""):
        _add_signal(
            signals,
            signal_type="via_header",
            source="header:via",
            value=headers["via"],
            weight=0.55,
            provider=EdgeProvider.FASTLY,
        )

    if "bunnycdn" in server or "bunnycdn" in headers.get("cdn-server", ""):
        _add_signal(
            signals,
            signal_type="cdn_server_header",
            source="header:server",
            value=server or headers.get("cdn-server", ""),
            weight=0.80,
            provider=EdgeProvider.BUNNYCDN,
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

    if (
        "server" in headers
        and "cdn" in server
        and not any(
            signal.provider is not None
            for signal in signals
        )
    ):
        _add_signal(
            signals,
            signal_type="generic_cdn_header",
            source="header:server",
            value=server,
            weight=0.55,
            provider=EdgeProvider.GENERIC_CDN,
        )

    provider, confidence = _provider_decision(signals)
    edge_detected = provider not in {
        EdgeProvider.NONE,
        EdgeProvider.MODSECURITY,
        EdgeProvider.GENERIC_WAF,
    }

    cloudflare_challenge = (
        headers.get("cf-mitigated") == "challenge"
        or (
            provider == EdgeProvider.CLOUDFLARE
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
            provider=provider,
            provider_confidence=confidence,
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

    waf_block_marker = any(
        marker in body
        for marker in (
            "incapsula incident id",
            "mod_security",
            "modsecurity",
            "request rejected",
            "web application firewall",
        )
    )

    if status in {403, 406} and waf_block_marker:
        if provider == EdgeProvider.NONE:
            provider = EdgeProvider.GENERIC_WAF
            confidence = max(confidence, 0.55)

        return EdgeAssessment(
            edge_detected=edge_detected,
            provider=provider,
            provider_confidence=confidence,
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
        return EdgeAssessment(
            edge_detected=True,
            provider=provider,
            provider_confidence=confidence,
            response_class=EdgeResponseClass.APPLICATION_RESPONSE,
            application_reachability=ApplicationReachability.PROBABLE,
            signals=signals,
            rationale=[
                (
                    "The response traversed a recognized edge/CDN layer "
                    "without explicit challenge or block evidence."
                ),
                (
                    "Application reachability remains probable rather than "
                    "confirmed until application-specific evidence is evaluated."
                ),
            ],
        )

    if provider in {
        EdgeProvider.MODSECURITY,
        EdgeProvider.GENERIC_WAF,
    }:
        return EdgeAssessment(
            edge_detected=False,
            provider=provider,
            provider_confidence=confidence,
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
        provider=EdgeProvider.NONE,
        provider_confidence=0.0,
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
