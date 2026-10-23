from typer.testing import CliRunner

from php_sentinel.cli import app

runner = CliRunner()


def test_scan_help_exposes_trusted_policy_options():
    result = runner.invoke(
        app,
        [
            "scan",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "--policy" in result.stdout
    assert "--manifest" in result.stdout
    assert "--trust-store" in result.stdout


def test_scan_rejects_external_policy_without_manifest(
    tmp_path,
):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        "{}",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "http://127.0.0.1:18080",
            "--policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == 4

    output = result.stdout.lower()

    assert "intelligence activation denied" in output
    assert "--manifest" in output
    assert "--trust-store" in output
