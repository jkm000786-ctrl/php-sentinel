import json
from unittest.mock import patch

import httpx
from typer.testing import CliRunner

from php_sentinel import cve_cli
from php_sentinel.cli import app
from php_sentinel.http.client import TransportExecutionError
from php_sentinel.intelligence import cve_database
from php_sentinel.models.transport import (
    TransportEvidence,
    TransportExecution,
    TransportStopReason,
)

runner = CliRunner()


def test_analyze_help_marks_diagnostic_authority_boundary():
    result = runner.invoke(app, ["analyze", "--help"])

    assert result.exit_code == 0
    assert "Bundled-policy diagnostic assessment" in result.stdout
    assert "canonical provenance-bearing assessment path" in result.stdout


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_analyze_inherits_transport_fail_closed_authority(mock_fetch):
    response = httpx.Response(
        302,
        headers={
            "Location": "https://other.test/",
            "X-Powered-By": "PHP/8.5.11",
        },
        content=b"redirect",
        request=httpx.Request(
            "GET",
            "https://example.test/",
        ),
    )

    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            redirect_target_denied=True,
            stop_reason=TransportStopReason.REDIRECT_TARGET_DENIED,
        )
    )

    mock_fetch.return_value = (response, transport)

    result = runner.invoke(
        app,
        [
            "analyze",
            "https://example.test/",
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(result.stdout)

    assert payload["status"] == "inconclusive"
    assert payload["php_detected"] is False
    assert payload["php_version"] is None
    assert payload["php_confidence"] == 0.0
    assert payload["exposure_priority"] == "unknown"
    assert payload["applicable_cves"] == []

    assert "NOTICE:" in result.stderr
    assert "does not emit canonical assessment provenance" in result.stderr


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_analyze_network_failure_exits_without_assessment(mock_fetch):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=TransportStopReason.TIMEOUT,
        )
    )

    mock_fetch.side_effect = TransportExecutionError(
        (
            "Transport execution failed before a permitted "
            "application response was obtained."
        ),
        evidence=transport,
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            "https://example.test/",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "HTTP error:" in result.stderr
    assert "PHP/8" not in result.stdout


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_scan_network_failure_exits_without_report(mock_fetch):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=TransportStopReason.NETWORK_ERROR,
        )
    )

    mock_fetch.side_effect = TransportExecutionError(
        (
            "Transport execution failed before a permitted "
            "application response was obtained."
        ),
        evidence=transport,
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.test/",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "HTTP error:" in result.stderr
    assert "Transport execution failed" in result.stderr
    assert "php_detected" not in result.stdout
    assert "provenance" not in result.stdout


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
