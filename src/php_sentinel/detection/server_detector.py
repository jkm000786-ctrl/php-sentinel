from __future__ import annotations

from php_sentinel.models.fingerprint import ServerFamily


def detect_server_family(server_header: str | None) -> ServerFamily:
    if not server_header:
        return ServerFamily.UNKNOWN

    value = server_header.lower()

    if "litespeed" in value:
        return ServerFamily.LITESPEED
    if "apache" in value:
        return ServerFamily.APACHE
    if "nginx" in value:
        return ServerFamily.NGINX
    if "caddy" in value:
        return ServerFamily.CADDY
    if "microsoft-iis" in value or "iis" in value:
        return ServerFamily.IIS

    return ServerFamily.UNKNOWN
