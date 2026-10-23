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
