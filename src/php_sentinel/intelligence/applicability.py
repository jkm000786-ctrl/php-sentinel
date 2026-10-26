from __future__ import annotations

from dataclasses import dataclass

from php_sentinel.intelligence.repository import default_policy
from php_sentinel.models.fingerprint import SAPIHypothesis
from php_sentinel.models.intelligence_policy import IntelligencePolicy


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
    policy: IntelligencePolicy | None = None,
) -> ApplicabilityDecision:
    selected_policy = policy or default_policy()
    cves = tuple(item.cve_id for item in selected_policy.cves)

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

    if sapi.value in selected_policy.sapi_priority.critical:
        priority = "critical"
        reasons.append(
            f"{sapi.value} is in the policy's critical web-serving deployment class."
        )
    elif sapi.value in selected_policy.sapi_priority.high:
        priority = "high"
        reasons.append(
            f"{sapi.value} is included in the policy's high-risk web-serving deployment class."
        )
    elif sapi.value == "unknown":
        priority = selected_policy.sapi_priority.unknown_priority
        reasons.append(
            "SAPI is unknown; exposure priority follows the policy's unknown-SAPI classification."
        )
    else:
        priority = selected_policy.sapi_priority.other_priority
        reasons.append(
            "SAPI is outside the explicitly prioritized classes; exposure priority follows "
            "the policy's fallback classification."
        )

    return ApplicabilityDecision(
        cves,
        True,
        priority,
        tuple(reasons),
    )
