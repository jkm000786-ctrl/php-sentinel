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
    assert result.waf_detected is True
    assert result.provider == EdgeProvider.CLOUDFLARE
    assert result.provider_confidence == 1.0
    assert result.response_class == EdgeResponseClass.BOT_CHALLENGE
    assert result.application_reachability == ApplicationReachability.NOT_REACHED
    assert result.challenge_detected is True


def test_cloudflare_php_response_is_probable_application_response():
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


def test_cloudflare_without_application_evidence_remains_edge_response():
    result = classify_edge_response(
        response(
            headers={
                "Server": "cloudflare",
                "CF-Ray": "abc123-KHI",
            },
            body="generic edge response",
        )
    )

    assert result.provider == EdgeProvider.CLOUDFLARE
    assert result.response_class == EdgeResponseClass.EDGE_RESPONSE
    assert result.application_reachability == ApplicationReachability.UNKNOWN


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
    assert result.waf_detected is True


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


def test_generic_request_rejected_text_is_not_waf_evidence():
    result = classify_edge_response(
        response(
            403,
            headers={"Server": "Apache"},
            body="Request rejected by application policy",
        )
    )

    assert result.provider == EdgeProvider.NONE
    assert result.waf_detected is False
    assert result.response_class == EdgeResponseClass.APPLICATION_RESPONSE
    assert result.application_reachability == ApplicationReachability.PROBABLE


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


def test_bunnycdn_without_php_evidence_remains_edge_response():
    result = classify_edge_response(
        response(
            headers={"Server": "BunnyCDN-PK1-1345"},
            body="normal response",
        )
    )

    assert result.edge_detected is True
    assert result.provider == EdgeProvider.BUNNYCDN
    assert result.response_class == EdgeResponseClass.EDGE_RESPONSE
    assert result.application_reachability == ApplicationReachability.UNKNOWN


def test_cloudfront_is_recognized_without_inventing_aws_waf():
    result = classify_edge_response(
        response(
            403,
            headers={
                "X-Amz-Cf-Id": "opaque-request-identifier",
                "X-Amz-Cf-Pop": "KHI50-P1",
                "Via": "1.1 example.cloudfront.net (CloudFront)",
            },
            body="Forbidden",
        )
    )

    assert result.edge_detected is True
    assert result.waf_detected is False
    assert result.provider == EdgeProvider.AWS_CLOUDFRONT
    assert result.response_class == EdgeResponseClass.EDGE_RESPONSE
    assert result.application_reachability == ApplicationReachability.UNKNOWN


def test_sucuri_block_requires_specific_waf_evidence():
    result = classify_edge_response(
        response(
            403,
            headers={
                "Server": "Sucuri/Cloudproxy",
                "X-Sucuri-ID": "12345",
            },
            body="Access Denied - Sucuri Website Firewall",
        )
    )

    assert result.provider == EdgeProvider.SUCURI
    assert result.waf_detected is True
    assert result.response_class == EdgeResponseClass.WAF_BLOCK
    assert result.application_reachability == ApplicationReachability.NOT_REACHED


def test_sucuri_edge_without_block_marker_is_not_called_waf_block():
    result = classify_edge_response(
        response(
            403,
            headers={
                "Server": "Sucuri/Cloudproxy",
                "X-Sucuri-ID": "12345",
            },
            body="Forbidden",
        )
    )

    assert result.provider == EdgeProvider.SUCURI
    assert result.waf_detected is False
    assert result.response_class == EdgeResponseClass.EDGE_RESPONSE
    assert result.application_reachability == ApplicationReachability.UNKNOWN


def test_azure_edge_reference_is_conservatively_attributed():
    result = classify_edge_response(
        response(
            headers={"X-Azure-Ref": "opaque-reference"},
            body="edge response",
        )
    )

    assert result.provider == EdgeProvider.AZURE_EDGE
    assert result.edge_detected is True
    assert result.response_class == EdgeResponseClass.EDGE_RESPONSE
    assert result.application_reachability == ApplicationReachability.UNKNOWN


def test_conflicting_strong_provider_signals_fail_to_unknown_attribution():
    result = classify_edge_response(
        response(
            headers={
                "Server": "cloudflare",
                "CF-Ray": "abc123-KHI",
                "X-Sucuri-ID": "67890",
                "X-Sucuri-Cache": "HIT",
            },
            body="intermediary response",
        )
    )

    assert result.edge_detected is True
    assert result.provider == EdgeProvider.UNKNOWN
    assert result.provider_ambiguous is True
    assert EdgeProvider.CLOUDFLARE in result.provider_candidates
    assert EdgeProvider.SUCURI in result.provider_candidates
    assert result.response_class == EdgeResponseClass.EDGE_RESPONSE
    assert result.application_reachability == ApplicationReachability.UNKNOWN


def test_opaque_edge_request_ids_are_not_retained_as_signal_values():
    result = classify_edge_response(
        response(
            headers={
                "Server": "cloudflare",
                "CF-Ray": "secret-looking-trace-value",
            },
            body="edge response",
        )
    )

    ray_signal = next(
        signal
        for signal in result.signals
        if signal.source == "header:cf-ray"
    )

    assert ray_signal.value == "present"
    assert "secret-looking-trace-value" not in result.model_dump_json()


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
    assert result.waf_detected is False
    assert result.provider == EdgeProvider.NONE
    assert result.provider_confidence == 0.0
    assert result.response_class == EdgeResponseClass.APPLICATION_RESPONSE
    assert result.application_reachability == ApplicationReachability.PROBABLE
