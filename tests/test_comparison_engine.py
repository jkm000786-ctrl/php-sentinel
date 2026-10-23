from unittest.mock import patch

import httpx

from php_sentinel.assessment.pipeline import (
    run_unified_assessment,
)
from php_sentinel.comparison.engine import (
    compare_reports,
)
from php_sentinel.models.vendor import VendorFamily


def response(version: str) -> httpx.Response:
    request = httpx.Request(
        "GET",
        "http://127.0.0.1/",
    )

    return httpx.Response(
        200,
        request=request,
        headers={
            "Server": "Apache/2.4.69 (Debian)",
            "X-Powered-By": f"PHP/{version}",
        },
        text=f"runtime={version}",
    )


@patch("php_sentinel.assessment.pipeline.fetch")
def test_candidate_to_patched_is_remediated(
    mock_fetch,
):
    mock_fetch.side_effect = [
        response("8.5.11"),
        response("8.5.12"),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.overall_state.value == "remediated"

    assert all(change.transition.value == "remediated" for change in result.cve_changes)


@patch("php_sentinel.assessment.pipeline.fetch")
def test_patched_to_candidate_is_regressed(
    mock_fetch,
):
    mock_fetch.side_effect = [
        response("8.5.12"),
        response("8.5.11"),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.overall_state.value == "regressed"


@patch("php_sentinel.assessment.pipeline.fetch")
def test_same_evidence_is_unchanged(
    mock_fetch,
):
    mock_fetch.side_effect = [
        response("8.5.12"),
        response("8.5.12"),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.overall_state.value == "unchanged"

    assert result.same_canonical_evidence is True


@patch("php_sentinel.assessment.pipeline.fetch")
def test_different_targets_are_incomparable_by_default(
    mock_fetch,
):
    mock_fetch.side_effect = [
        response("8.5.11"),
        response("8.5.12"),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1:18081/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1:18080/",
        vendor=VendorFamily.UPSTREAM,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.same_requested_target is False
    assert result.overall_state.value == "incomparable"

    assert all(change.transition.value == "remediated" for change in result.cve_changes)


@patch("php_sentinel.assessment.pipeline.fetch")
def test_cross_target_override_allows_lab_comparison(
    mock_fetch,
):
    mock_fetch.side_effect = [
        response("8.5.11"),
        response("8.5.12"),
    ]

    before = run_unified_assessment(
        "http://127.0.0.1:18081/",
        vendor=VendorFamily.UPSTREAM,
    )

    after = run_unified_assessment(
        "http://127.0.0.1:18080/",
        vendor=VendorFamily.UPSTREAM,
    )

    result = compare_reports(
        before,
        after,
        allow_cross_target=True,
    )

    assert result.same_requested_target is False
    assert result.overall_state.value == "remediated"


@patch("php_sentinel.assessment.pipeline.fetch")
def test_policy_change_is_explicitly_reported(
    mock_fetch,
):
    from php_sentinel.intelligence.repository import (
        default_policy,
    )

    mock_fetch.side_effect = [
        response("8.5.12"),
        response("8.5.12"),
    ]

    before_policy = default_policy()

    after_policy = before_policy.model_copy(deep=True)

    after_policy.fixed_versions["8.5"] = "8.5.13"

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
        intelligence_policy=before_policy,
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
        intelligence_policy=after_policy,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.same_requested_target is True

    assert result.same_intelligence_policy is False

    assert result.overall_state.value == "policy_changed"

    text = " ".join(result.changes).lower()

    assert "intelligence policy changed" in text


@patch("php_sentinel.assessment.pipeline.fetch")
def test_trust_change_is_explicitly_reported(
    mock_fetch,
):
    from php_sentinel.intelligence.repository import (
        default_policy,
        policy_sha256,
    )
    from php_sentinel.models.intelligence_trust import (
        IntelligenceTrustDecision,
        IntelligenceTrustState,
    )

    mock_fetch.side_effect = [
        response("8.5.12"),
        response("8.5.12"),
    ]

    policy = default_policy()

    before = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
        intelligence_policy=policy,
    )

    signed = IntelligenceTrustDecision(
        state=IntelligenceTrustState.TRUSTED,
        trusted=True,
        policy_id=policy.policy_id,
        policy_sha256=policy_sha256(policy),
        signer_id="test-signer",
        algorithm="ed25519",
        rationale=["test trust transition"],
    )

    after = run_unified_assessment(
        "http://127.0.0.1/",
        vendor=VendorFamily.UPSTREAM,
        intelligence_policy=policy,
        intelligence_trust=signed,
    )

    result = compare_reports(
        before,
        after,
    )

    assert result.same_intelligence_policy is True

    assert result.same_intelligence_trust is False

    assert result.overall_state.value == "trust_changed"
