from __future__ import annotations

import httpx

from php_sentinel.detection.edge_detector import classify_edge_response
from php_sentinel.models.edge import (
    ApplicationReachability,
    EdgeProvider,
    EdgeResponseClass,
)


def response(
    status: int = 200,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
) -> httpx.Response:
    return httpx.Response(
        status,
        request=httpx.Request("GET", "https://example.test/"),
        headers=headers or {},
        text=body,
    )


def test_cloudflare_challenge_is_not_application_evidence():
    result = classify_edge_response(
        response(
            403,
            headers={
                "Server": "cloudflare",
                "CF-Ray": "abc123-KHI",
                "CF-Mitigated": "challenge",
            },
            body="<title>Just a moment...</title>",
        )
    )

    assert result.edge_detected is True
    assert result.provider == EdgeProvider.CLOUDFLARE
    assert result.provider_confidence == 1.0
    assert result.response_class == EdgeResponseClass.BOT_CHALLENGE
    assert result.application_reachability == ApplicationReachability.NOT_REACHED
    assert result.challenge_detected is True


def test_cloudflare_normal_response_is_probable_application_response():
    result = classify_edge_response(
        response(
            headers={
                "Server": "cloudflare",
                "CF-Ray": "abc123-KHI",
                "X-Powered-By": "PHP/8.5.12",
            },
            body="application response",
        )
    )

    assert result.provider == EdgeProvider.CLOUDFLARE
    assert result.response_class == EdgeResponseClass.APPLICATION_RESPONSE
    assert result.application_reachability == ApplicationReachability.PROBABLE
    assert result.challenge_detected is False


def test_imperva_block_is_classified_fail_closed():
    result = classify_edge_response(
        response(
            403,
            headers={
                "X-Iinfo": "5-123456-0 0NNN RT(1)",
                "X-CDN": "Imperva",
            },
            body="Request unsuccessful. Incapsula incident ID: 123456",
        )
    )

    assert result.provider == EdgeProvider.IMPERVA
    assert result.provider_confidence == 1.0
    assert result.response_class == EdgeResponseClass.WAF_BLOCK
    assert result.application_reachability == ApplicationReachability.NOT_REACHED


def test_modsecurity_block_can_be_identified_without_cdn_provider():
    result = classify_edge_response(
        response(
            403,
            headers={"Server": "Apache"},
            body="Request rejected by ModSecurity",
        )
    )

    assert result.provider == EdgeProvider.MODSECURITY
    assert result.response_class == EdgeResponseClass.WAF_BLOCK
    assert result.application_reachability == ApplicationReachability.NOT_REACHED


def test_generic_403_is_not_assumed_to_be_waf_block():
    result = classify_edge_response(
        response(
            403,
            headers={"Server": "Apache"},
            body="Forbidden",
        )
    )

    assert result.provider == EdgeProvider.NONE
    assert result.response_class == EdgeResponseClass.APPLICATION_RESPONSE
    assert result.application_reachability == ApplicationReachability.PROBABLE


def test_rate_limit_does_not_assume_limiting_layer():
    result = classify_edge_response(
        response(
            429,
            headers={"Retry-After": "60"},
            body="Too Many Requests",
        )
    )

    assert result.response_class == EdgeResponseClass.RATE_LIMIT
    assert result.application_reachability == ApplicationReachability.UNKNOWN
    assert result.rate_limited is True


def test_edge_origin_failure_is_not_application_evidence():
    result = classify_edge_response(
        response(
            503,
            headers={
                "Server": "cloudflare",
                "CF-Ray": "failure-KHI",
            },
            body="Service unavailable",
        )
    )

    assert result.provider == EdgeProvider.CLOUDFLARE
    assert result.response_class == EdgeResponseClass.ORIGIN_FAILURE
    assert result.application_reachability == ApplicationReachability.NOT_REACHED


def test_bunnycdn_is_recognized_without_becoming_a_block():
    result = classify_edge_response(
        response(
            headers={"Server": "BunnyCDN-PK1-1345"},
            body="normal response",
        )
    )

    assert result.edge_detected is True
    assert result.provider == EdgeProvider.BUNNYCDN
    assert result.response_class == EdgeResponseClass.APPLICATION_RESPONSE
    assert result.application_reachability == ApplicationReachability.PROBABLE


def test_direct_php_response_does_not_invent_edge_provider():
    result = classify_edge_response(
        response(
            headers={
                "Server": "Apache/2.4.69",
                "X-Powered-By": "PHP/8.5.12",
            },
            body="runtime",
        )
    )

    assert result.edge_detected is False
    assert result.provider == EdgeProvider.NONE
    assert result.provider_confidence == 0.0
    assert result.response_class == EdgeResponseClass.APPLICATION_RESPONSE
    assert result.application_reachability == ApplicationReachability.PROBABLE
