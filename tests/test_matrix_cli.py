from pathlib import Path
from unittest.mock import patch

import pytest
import typer

from php_sentinel.intelligence.activation import IntelligenceActivationError
from php_sentinel.matrix_cli import main


def _call_main(
    tmp_path: Path,
    *,
    policy_path: Path | None = None,
    manifest_path: Path | None = None,
    trust_store_path: Path | None = None,
) -> None:
    main(
        candidate="http://127.0.0.1:18081/",
        patched_reference="http://127.0.0.1:18080/",
        authorize_lab=True,
        evidence_out=None,
        timeout=10.0,
        policy_path=policy_path,
        manifest_path=manifest_path,
        trust_store_path=trust_store_path,
        minimum_policy_generation=1,
        max_policy_age_days=30,
        lifecycle_state_path=tmp_path / "lifecycle.json",
        version=False,
    )


@patch("php_sentinel.matrix_cli.compare_lab_targets")
@patch("php_sentinel.matrix_cli.activate_verified_intelligence")
def test_matrix_cli_fails_closed_when_intelligence_activation_is_denied(
    activate,
    compare,
    tmp_path,
):
    activate.side_effect = IntelligenceActivationError("trust denied")

    with pytest.raises(typer.Exit) as exc:
        _call_main(
            tmp_path,
            policy_path=tmp_path / "policy.json",
            manifest_path=tmp_path / "manifest.json",
            trust_store_path=tmp_path / "trust.json",
        )

    assert exc.value.exit_code == 4
    compare.assert_not_called()


@patch("php_sentinel.matrix_cli.compare_lab_targets")
@patch("php_sentinel.matrix_cli.activate_verified_intelligence")
def test_matrix_cli_passes_verified_selection_to_differential_engine(
    activate,
    compare,
    tmp_path,
):
    verified_selection = object()
    activate.return_value = verified_selection
    compare.side_effect = RuntimeError("stop after propagation")

    with pytest.raises(RuntimeError, match="stop after propagation"):
        _call_main(tmp_path)

    _, kwargs = compare.call_args
    assert kwargs["intelligence_selection"] is verified_selection
    assert kwargs["explicit_authorization"] is True
    assert kwargs["timeout"] == 10.0
