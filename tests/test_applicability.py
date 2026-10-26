from php_sentinel.intelligence.applicability import (
    evaluate_oct_2026_applicability,
)
from php_sentinel.models.fingerprint import SAPIHypothesis


def test_mod_php_gets_critical_priority():
    decision = evaluate_oct_2026_applicability(
        php_detected=True,
        upstream_fixed=False,
        sapi=SAPIHypothesis.MOD_PHP,
    )
    assert decision.applicable is True
    assert decision.exposure_priority == "critical"


def test_fixed_version_not_applicable():
    decision = evaluate_oct_2026_applicability(
        php_detected=True,
        upstream_fixed=True,
        sapi=SAPIHypothesis.MOD_PHP,
    )
    assert decision.applicable is False


def test_applicability_accepts_policy_injection():
    from php_sentinel.intelligence.repository import default_policy

    policy = default_policy().model_copy(deep=True)
    policy.sapi_priority.critical.remove("mod_php")
    policy.sapi_priority.high.append("mod_php")

    decision = evaluate_oct_2026_applicability(
        php_detected=True,
        upstream_fixed=False,
        sapi=SAPIHypothesis.MOD_PHP,
        policy=policy,
    )

    assert decision.exposure_priority == "high"
    assert set(decision.cves) == {item.cve_id for item in policy.cves}


def test_unknown_sapi_uses_policy_priority():
    from php_sentinel.intelligence.repository import default_policy

    policy = default_policy().model_copy(deep=True)
    policy.sapi_priority.unknown_priority = "unknown"

    decision = evaluate_oct_2026_applicability(
        php_detected=True,
        upstream_fixed=False,
        sapi=SAPIHypothesis.UNKNOWN,
        policy=policy,
    )

    assert decision.exposure_priority == "unknown"
