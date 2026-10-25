from __future__ import annotations

from dataclasses import dataclass

from php_sentinel.models.fingerprint import SAPIHypothesis, ServerFamily


@dataclass(frozen=True)
class SAPIDecision:
    sapi: SAPIHypothesis
    confidence: float
    indicators: tuple[str, ...]


def infer_sapi(
    *,
    server_family: ServerFamily,
    server_header: str | None,
    x_powered_by: str | None,
    body: str,
) -> SAPIDecision:
    indicators: list[str] = []
    body_lower = body.lower()
    server_lower = (server_header or "").lower()

    if "frankenphp" in server_lower:
        return SAPIDecision(
            SAPIHypothesis.FRANKENPHP,
            0.95,
            ("FrankenPHP server marker observed",),
        )

    if server_family == ServerFamily.LITESPEED:
        return SAPIDecision(
            SAPIHypothesis.LITESPEED,
            0.90,
            ("LiteSpeed server marker observed",),
        )

    if "fpm/fcgi" in body_lower or "php-fpm" in body_lower:
        return SAPIDecision(
            SAPIHypothesis.FPM_FASTCGI,
            0.95,
            ("Explicit PHP-FPM/FastCGI marker observed",),
        )

    if "cgi-fcgi" in body_lower:
        return SAPIDecision(
            SAPIHypothesis.FPM_FASTCGI,
            0.90,
            ("CGI/FastCGI SAPI marker observed",),
        )

    if "cgi/fastcgi" in body_lower:
        return SAPIDecision(
            SAPIHypothesis.FPM_FASTCGI,
            0.90,
            ("FastCGI marker observed",),
        )

    if "cgi" in body_lower and "sapi" in body_lower:
        return SAPIDecision(
            SAPIHypothesis.CGI,
            0.80,
            ("CGI SAPI marker observed",),
        )

    if server_family == ServerFamily.APACHE and x_powered_by:
        indicators.append("Apache and PHP header observed together")
        return SAPIDecision(
            SAPIHypothesis.MOD_PHP,
            0.55,
            tuple(indicators),
        )

    if server_family == ServerFamily.NGINX and x_powered_by:
        indicators.append("nginx and PHP header observed")
        indicators.append("nginx commonly proxies PHP through FastCGI")
        return SAPIDecision(
            SAPIHypothesis.FPM_FASTCGI,
            0.45,
            tuple(indicators),
        )

    return SAPIDecision(
        SAPIHypothesis.UNKNOWN,
        0.0,
        ("No reliable SAPI evidence observed",),
    )
