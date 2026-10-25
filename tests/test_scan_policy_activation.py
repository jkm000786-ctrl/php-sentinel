from typer.testing import CliRunner

from php_sentinel.cli import app

runner = CliRunner()


def test_scan_help_exposes_trusted_policy_options():
    from typer.main import get_command

    root = get_command(app)
    scan_command = root.commands["scan"]

    option_names = {
        option
        for param in scan_command.params
        for option in getattr(param, "opts", [])
    }

    assert "--policy" in option_names
    assert "--manifest" in option_names
    assert "--trust-store" in option_names


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


def test_scan_help_exposes_lifecycle_controls():
    from typer.main import get_command

    root = get_command(app)

    scan_command = root.commands["scan"]

    option_names = {
        option
        for param in scan_command.params
        for option in getattr(
            param,
            "opts",
            [],
        )
    }

    assert "--minimum-policy-generation" in option_names
    assert "--max-policy-age-days" in option_names
    assert "--lifecycle-state" in option_names
