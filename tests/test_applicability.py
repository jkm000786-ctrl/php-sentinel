from php_sentinel.intelligence.applicability import (
    evaluate_oct_2026_applicability,
)
from php_sentinel.models.fingerprint import SAPIHypothesis


def test_mod_php_gets_highest_priority():
    decision = evaluate_oct_2026_applicability(
        php_detected=True,
        upstream_fixed=False,
        sapi=SAPIHypothesis.MOD_PHP,
    )
    assert decision.applicable is True
    assert decision.exposure_priority == "highest"


def test_fixed_version_not_applicable():
    decision = evaluate_oct_2026_applicability(
        php_detected=True,
        upstream_fixed=True,
        sapi=SAPIHypothesis.MOD_PHP,
    )
    assert decision.applicable is False
