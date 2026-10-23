from unittest.mock import patch

from php_sentinel.models.validation import (
    ValidationKind,
    ValidationObservation,
    ValidationReport,
)
from php_sentinel.validation.differential import (
    compare_lab_targets,
)


def report(
    target: str,
    version: str,
    body_hash: str,
) -> ValidationReport:
    return ValidationReport(
        target=target,
        authorized=True,
        observations=[
            ValidationObservation(
                kind=ValidationKind.BASELINE_GET,
                method="GET",
                url=target,
                status_code=200,
                server="Apache",
                x_powered_by=f"PHP/{version}",
                body_sha256=body_hash,
                body_length=10,
            )
        ],
    )


@patch("php_sentinel.validation.differential.run_lab_validation")
def test_candidate_vs_patched_precondition_difference(run):
    run.side_effect = [
        report(
            "http://127.0.0.1:18081/",
            "8.5.11",
            "candidate",
        ),
        report(
            "http://127.0.0.1:18080/",
            "8.5.12",
            "patched",
        ),
    ]

    result = compare_lab_targets(
        "http://127.0.0.1:18081/",
        "http://127.0.0.1:18080/",
        explicit_authorization=True,
    )

    assert result.authorized is True
    assert result.conclusion.value == "precondition_differential_confirmed"
    assert result.candidate.upstream_fixed is False
    assert result.patched_reference.upstream_fixed is True


@patch("php_sentinel.validation.differential.run_lab_validation")
def test_matrix_never_claims_exploitability(run):
    run.side_effect = [
        report(
            "http://127.0.0.1:18081/",
            "8.5.11",
            "candidate",
        ),
        report(
            "http://127.0.0.1:18080/",
            "8.5.12",
            "patched",
        ),
    ]

    result = compare_lab_targets(
        "http://127.0.0.1:18081/",
        "http://127.0.0.1:18080/",
        explicit_authorization=True,
    )

    joined = " ".join(result.notes).lower()

    assert "does not establish exploitability" in joined
    assert "command execution" in joined
