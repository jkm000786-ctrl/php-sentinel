from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from php_sentinel.models.scope import (
    AuthorizationMode,
    ScopeDecision,
    ScopeEvaluation,
    ScopePolicy,
)

LOOPBACK_NAMES = {
    "localhost",
    "localhost.localdomain",
}


def _host_resolves_only_to_loopback(host: str) -> tuple[bool, list[str]]:
    if host.lower() in LOOPBACK_NAMES:
        return True, ["Target hostname is an explicit localhost name."]

    try:
        direct = ipaddress.ip_address(host)
    except ValueError:
        direct = None

    if direct is not None:
        if direct.is_loopback:
            return True, [f"{host} is a loopback address."]
        return False, [f"{host} is not a loopback address."]

    try:
        answers = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, ["Target hostname could not be resolved."]

    addresses: set[str] = set()

    for answer in answers:
        address = answer[4][0]
        addresses.add(address)

    if not addresses:
        return False, ["No target addresses were resolved."]

    non_loopback = []

    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            non_loopback.append(address)
            continue

        if not parsed.is_loopback:
            non_loopback.append(address)

    if non_loopback:
        return False, [
            "Target resolved to non-loopback address(es): " + ", ".join(sorted(non_loopback))
        ]

    return True, ["All resolved target addresses are loopback addresses."]


def evaluate_scope(policy: ScopePolicy) -> ScopeEvaluation:
    parsed = urlparse(str(policy.target))
    host = parsed.hostname

    if not host:
        return ScopeEvaluation(
            decision=ScopeDecision.DENY,
            reasons=["Target URL does not contain a hostname."],
        )

    if policy.mode == AuthorizationMode.PASSIVE:
        return ScopeEvaluation(
            decision=ScopeDecision.ALLOW,
            reasons=["Passive assessment mode is permitted."],
        )

    if not policy.explicit_authorization:
        return ScopeEvaluation(
            decision=ScopeDecision.DENY,
            reasons=["Lab validation requires explicit authorization."],
        )

    loopback, reasons = _host_resolves_only_to_loopback(host)

    if not loopback:
        return ScopeEvaluation(
            decision=ScopeDecision.DENY,
            reasons=reasons + ["Phase 4 active validation is restricted to loopback lab targets."],
        )

    if policy.allowed_hosts and host not in policy.allowed_hosts:
        return ScopeEvaluation(
            decision=ScopeDecision.DENY,
            reasons=[f"Host {host!r} is not present in the explicit allowlist."],
        )

    return ScopeEvaluation(
        decision=ScopeDecision.ALLOW,
        reasons=reasons
        + [
            "Explicit authorization is present.",
            "Target is within the Phase 4 loopback-only validation boundary.",
        ],
    )
