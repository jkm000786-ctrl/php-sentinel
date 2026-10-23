from __future__ import annotations

from dataclasses import dataclass

from php_sentinel.intelligence.cve_database import OCT_2026_CRITICAL
from php_sentinel.models.fingerprint import SAPIHypothesis


@dataclass(frozen=True)
class ApplicabilityDecision:
    cves: tuple[str, ...]
    applicable: bool
    exposure_priority: str
    rationale: tuple[str, ...]


def evaluate_oct_2026_applicability(
    *,
    php_detected: bool,
    upstream_fixed: bool | None,
    sapi: SAPIHypothesis,
) -> ApplicabilityDecision:
    cves = tuple(item.cve for item in OCT_2026_CRITICAL)

    if not php_detected:
        return ApplicabilityDecision(
            (),
            False,
            "none",
            ("PHP was not established from available evidence.",),
        )

    if upstream_fixed is True:
        return ApplicabilityDecision(
            (),
            False,
            "none",
            ("Detected upstream PHP version meets the fixed threshold.",),
        )

    priority = "unknown"
    reasons = ["PHP web-serving installations are in the advisory exposure class."]

    if sapi == SAPIHypothesis.MOD_PHP:
        priority = "highest"
        reasons.append(
            "Apache mod_php is identified by PHP upstream as the highest-risk deployment class."
        )
    elif sapi in {
        SAPIHypothesis.FPM_FASTCGI,
        SAPIHypothesis.CGI,
        SAPIHypothesis.FRANKENPHP,
        SAPIHypothesis.LITESPEED,
    }:
        priority = "high"
        reasons.append(
            f"{sapi.value} is included in the PHP upstream affected web-serving deployment classes."
        )
    else:
        priority = "undetermined"
        reasons.append("SAPI is unknown, so deployment-specific exposure cannot yet be ranked.")

    return ApplicabilityDecision(
        cves,
        True,
        priority,
        tuple(reasons),
    )
