import json

from typer.testing import CliRunner

from php_sentinel import cve_cli
from php_sentinel.cli import app
from php_sentinel.intelligence import cve_database

runner = CliRunner()


def test_analyze_help_marks_diagnostic_authority_boundary():
    result = runner.invoke(app, ["analyze", "--help"])

    assert result.exit_code == 0
    assert "Bundled-policy diagnostic assessment" in result.stdout
    assert "canonical provenance-bearing assessment path" in result.stdout


def test_legacy_cve_database_does_not_retain_policy_object():
    assert not hasattr(cve_database, "_POLICY")


def test_standalone_cve_evidence_marks_diagnostic_boundary(tmp_path, capsys):
    evidence_path = tmp_path / "cve-diagnostic.json"

    cve_cli.main(
        php_version="8.5.12",
        php_detected=True,
        vendor="upstream",
        backport_status="unknown",
        sapi="mod_php",
        evidence_out=evidence_path,
        version=False,
    )

    payload = json.loads(evidence_path.read_text(encoding="utf-8"))

    assert payload["notes"]
    assert "bundled-policy diagnostic" in payload["notes"][0]
    assert "canonical assessment provenance" in payload["notes"][0]

    captured = capsys.readouterr()
    assert "NOTICE:" in captured.err
    assert "authoritative provenance-bearing assessment" in captured.err
