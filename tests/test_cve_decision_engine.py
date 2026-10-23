from php_sentinel.intelligence.cve_decision_engine import decide_cves


def statuses(report):
    return {item.status.value for item in report.decisions}


def test_patched_8512():
    report = decide_cves(
        php_detected=True,
        php_version="8.5.12",
        vendor_family="upstream",
        sapi_hypothesis="mod_php",
    )

    assert statuses(report) == {"patched_upstream"}


def test_candidate_8511_upstream():
    report = decide_cves(
        php_detected=True,
        php_version="8.5.11",
        vendor_family="upstream",
        sapi_hypothesis="mod_php",
    )

    assert statuses(report) == {"potentially_affected"}

    for item in report.decisions:
        assert item.confidence.value == "high"
        assert item.exposure_priority.value == "critical"


def test_confirmed_vendor_backport():
    report = decide_cves(
        php_detected=True,
        php_version="8.5.11",
        vendor_family="ubuntu",
        backport_status="confirmed_fixed",
        sapi_hypothesis="fpm_fastcgi",
    )

    assert statuses(report) == {"patched_vendor"}


def test_old_banner_without_vendor_evidence():
    report = decide_cves(
        php_detected=True,
        php_version="8.5.11",
        vendor_family="ubuntu",
        backport_status="unknown",
        sapi_hypothesis="fpm_fastcgi",
    )

    assert statuses(report) == {"needs_vendor_evidence"}


def test_php_not_detected():
    report = decide_cves(
        php_detected=False,
        php_version=None,
    )

    assert statuses(report) == {"not_applicable"}


def test_missing_version_is_inconclusive():
    report = decide_cves(
        php_detected=True,
        php_version=None,
        sapi_hypothesis="unknown",
    )

    assert statuses(report) == {"inconclusive"}


def test_all_fixed_thresholds():
    cases = (
        "8.5.12",
        "8.4.27",
        "8.3.36",
        "8.2.35",
    )

    for version in cases:
        report = decide_cves(
            php_detected=True,
            php_version=version,
            vendor_family="upstream",
        )

        assert statuses(report) == {"patched_upstream"}


def test_unmodeled_branch_requires_vendor_evidence():
    report = decide_cves(
        php_detected=True,
        php_version="8.1.99",
        vendor_family="unknown",
    )

    assert statuses(report) == {"needs_vendor_evidence"}


def test_109619_contains_session_upload_advisory():
    report = decide_cves(
        php_detected=True,
        php_version="8.5.11",
        vendor_family="upstream",
        sapi_hypothesis="mod_php",
    )

    decision = next(item for item in report.decisions if item.cve_id == "CVE-2026-109619")

    text = " ".join(decision.remediation)

    assert "session.upload_progress.enabled=0" in text


def test_decision_engine_accepts_policy_injection():
    from php_sentinel.intelligence.repository import (
        default_policy,
    )

    policy = default_policy().model_copy(deep=True)

    policy.fixed_versions["8.5"] = "8.5.13"

    report = decide_cves(
        php_detected=True,
        php_version="8.5.12",
        vendor_family="upstream",
        sapi_hypothesis="mod_php",
        policy=policy,
    )

    assert statuses(report) == {"potentially_affected"}

    assert all(item.fixed_version == "8.5.13" for item in report.decisions)
