from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlparse

from php_sentinel.models.edge import (
    ApplicationReachability,
    EdgeAssessment,
    EdgeResponseClass,
)
from php_sentinel.models.edge_authority import (
    DifferentialEvidenceAuthority,
    EdgeAuthorityDecision,
    WAFDifferentialEvidence,
)


def _is_loopback_url(value: str) -> bool:
    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        return False

    host = parsed.hostname

    if host is None:
        return False

    if host.lower() == "localhost":
        return True

    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def validate_waf_differential_binding(
    *,
    target: str,
    final_url: str,
    observed_http_status: int,
    evidence: WAFDifferentialEvidence,
) -> None:
    if (
        evidence.authority
        == DifferentialEvidenceAuthority.AUTHORIZED_LOCAL_LAB
    ) and (
        not _is_loopback_url(target)
        or not _is_loopback_url(final_url)
    ):
        raise ValueError(
            "Authorized local-lab differential evidence may only "
            "be applied to loopback targets and final URLs."
        )

    if (
        evidence.protected_http_status
        != observed_http_status
    ):
        raise ValueError(
            "Differential evidence protected HTTP status does not "
            "match the observed protected response status."
        )


def resolve_edge_authority(
    passive: EdgeAssessment,
    *,
    differential_evidence: WAFDifferentialEvidence | None = None,
) -> EdgeAuthorityDecision:
    """Resolve effective edge authority without weakening passive classification."""

    if differential_evidence is None:
        passive_interception = (
            passive.waf_detected
            and passive.response_class == EdgeResponseClass.WAF_BLOCK
            and passive.application_reachability
            == ApplicationReachability.NOT_REACHED
        )

        return EdgeAuthorityDecision(
            passive=passive,
            effective_response_class=passive.response_class,
            effective_application_reachability=passive.application_reachability,
            waf_interception_established=passive_interception,
        )

    rationale = (
        (
            "Authorized differential evidence established WAF interruption "
            "before application reachability."
        ),
        (
            "Differential evidence may reduce application certainty only; "
            "it does not establish PHP runtime or CVE applicability."
        ),
        *differential_evidence.rationale,
    )

    return EdgeAuthorityDecision(
        passive=passive,
        effective_response_class=EdgeResponseClass.WAF_BLOCK,
        effective_application_reachability=ApplicationReachability.NOT_REACHED,
        waf_interception_established=True,
        constrained_by_differential=True,
        differential_evidence=differential_evidence,
        rationale=rationale,
    )
