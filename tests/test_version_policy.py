from php_sentinel.intelligence.version_policy import evaluate_version


def test_php_8512_is_fixed():
    assert evaluate_version("8.5.12").upstream_fixed is True


def test_php_8511_is_below_threshold():
    d = evaluate_version("8.5.11")
    assert d.upstream_fixed is False
    assert d.requires_vendor_evidence is True


def test_php_8427_is_fixed():
    assert evaluate_version("8.4.27").upstream_fixed is True


def test_php_8335_is_below_threshold():
    assert evaluate_version("8.3.35").upstream_fixed is False


def test_old_branch_requires_vendor_evidence():
    d = evaluate_version("7.4.33")
    assert d.upstream_fixed is None
    assert d.requires_vendor_evidence is True


def test_evaluate_version_accepts_policy_injection():
    from php_sentinel.intelligence.repository import default_policy

    policy = default_policy().model_copy(deep=True)
    policy.fixed_versions["8.5"] = "8.5.13"

    decision = evaluate_version("8.5.12", policy=policy)

    assert decision.upstream_fixed is False
    assert decision.requires_vendor_evidence is True
    assert "8.5.13" in decision.rationale
