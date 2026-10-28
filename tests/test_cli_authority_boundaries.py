import json
from unittest.mock import patch

import httpx
from typer.testing import CliRunner

from php_sentinel import cve_cli
from php_sentinel.cli import app
from php_sentinel.http.client import (
    HTTPResponseTooLargeError,
    TransportExecutionError,
)
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


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_analyze_body_limit_failure_exits_without_assessment(
    mock_fetch,
):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=(
                TransportStopReason.RESPONSE_BODY_LIMIT_EXCEEDED
            ),
        )
    )

    mock_fetch.side_effect = HTTPResponseTooLargeError(
        "Target HTTP response exceeds the maximum allowed body size.",
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
    assert "maximum allowed body size" in result.stderr
    assert "php_detected" not in result.stdout


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_scan_body_limit_failure_exits_without_report(
    mock_fetch,
    tmp_path,
):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=(
                TransportStopReason.RESPONSE_BODY_LIMIT_EXCEEDED
            ),
        )
    )

    mock_fetch.side_effect = HTTPResponseTooLargeError(
        "Target HTTP response exceeds the maximum allowed body size.",
        evidence=transport,
    )

    evidence_path = tmp_path / "must-not-exist.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.test/",
            "--json",
            "--evidence-out",
            str(evidence_path),
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "HTTP error:" in result.stderr
    assert "maximum allowed body size" in result.stderr
    assert "assessment" not in result.stdout
    assert "provenance" not in result.stdout
    assert not evidence_path.exists()


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_analyze_network_failure_writes_separate_failure_evidence(
    mock_fetch,
    tmp_path,
):
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

    requested_path = tmp_path / "analysis.json"

    result = runner.invoke(
        app,
        [
            "analyze",
            "https://example.test/",
            "--json",
            "--evidence-out",
            str(requested_path),
        ],
    )

    failure_path = (
        tmp_path
        / "analysis-operational-failure.json"
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert not requested_path.exists()
    assert failure_path.exists()

    payload = json.loads(
        failure_path.read_text(
            encoding="utf-8",
        )
    )

    assert payload["artifact_type"] == "operational_failure"
    assert payload["schema_version"] == 1
    assert payload["failure_reason"] == "timeout"
    assert payload["complete_response_available"] is False
    assert payload["assessment_available"] is False
    assert (
        payload["transport"]["execution"]["stop_reason"]
        == "timeout"
    )

    assert "http" not in payload
    assert "assessment" not in payload
    assert "provenance" not in payload
    assert "generated_at" not in payload

    assert (
        "Operational failure evidence written:"
        in result.stderr
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_scan_body_limit_writes_separate_failure_evidence(
    mock_fetch,
    tmp_path,
):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=(
                TransportStopReason.RESPONSE_BODY_LIMIT_EXCEEDED
            ),
        )
    )

    mock_fetch.side_effect = HTTPResponseTooLargeError(
        "Target HTTP response exceeds the maximum allowed body size.",
        evidence=transport,
    )

    requested_path = tmp_path / "scan.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.test/",
            "--json",
            "--evidence-out",
            str(requested_path),
        ],
    )

    failure_path = (
        tmp_path
        / "scan-operational-failure.json"
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert not requested_path.exists()
    assert failure_path.exists()

    payload = json.loads(
        failure_path.read_text(
            encoding="utf-8",
        )
    )

    assert payload["artifact_type"] == "operational_failure"
    assert (
        payload["failure_reason"]
        == "response_body_limit_exceeded"
    )
    assert (
        payload["transport"]["execution"]["stop_reason"]
        == "response_body_limit_exceeded"
    )

    assert payload["complete_response_available"] is False
    assert payload["assessment_available"] is False

    assert "http" not in payload
    assert "assessment" not in payload
    assert "provenance" not in payload
    assert "generated_at" not in payload

    assert (
        "Operational failure evidence written:"
        in result.stderr
    )


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_scan_network_failure_writes_operational_evidence(
    mock_fetch,
    tmp_path,
):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=TransportStopReason.NETWORK_ERROR,
        )
    )

    mock_fetch.side_effect = TransportExecutionError(
        "network unavailable",
        evidence=transport,
    )

    requested_path = tmp_path / "network.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.test/",
            "--json",
            "--evidence-out",
            str(requested_path),
        ],
    )

    failure_path = (
        tmp_path
        / "network-operational-failure.json"
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert not requested_path.exists()
    assert failure_path.exists()

    payload = json.loads(
        failure_path.read_text(
            encoding="utf-8",
        )
    )

    assert payload["failure_reason"] == "network_error"
    assert payload["tool_name"] == "php-sentinel"
    assert payload["tool_version"]
    assert "http" not in payload
    assert "assessment" not in payload


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_analyze_body_limit_writes_operational_evidence(
    mock_fetch,
    tmp_path,
):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=(
                TransportStopReason.RESPONSE_BODY_LIMIT_EXCEEDED
            ),
        )
    )

    mock_fetch.side_effect = HTTPResponseTooLargeError(
        "Target HTTP response exceeds the maximum allowed body size.",
        evidence=transport,
    )

    requested_path = tmp_path / "body.json"

    result = runner.invoke(
        app,
        [
            "analyze",
            "https://example.test/",
            "--json",
            "--evidence-out",
            str(requested_path),
        ],
    )

    failure_path = (
        tmp_path
        / "body-operational-failure.json"
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert not requested_path.exists()
    assert failure_path.exists()

    payload = json.loads(
        failure_path.read_text(
            encoding="utf-8",
        )
    )

    assert (
        payload["failure_reason"]
        == "response_body_limit_exceeded"
    )
    assert payload["tool_name"] == "php-sentinel"
    assert payload["tool_version"]
    assert "http" not in payload
    assert "assessment" not in payload


@patch("php_sentinel.assessment.pipeline.fetch_with_transport")
def test_http_error_without_transport_evidence_does_not_fabricate_artifact(
    mock_fetch,
    tmp_path,
):
    mock_fetch.side_effect = httpx.ConnectError(
        "connection failed without attached transport evidence"
    )

    requested_path = tmp_path / "missing-evidence.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.test/",
            "--json",
            "--evidence-out",
            str(requested_path),
        ],
    )

    failure_path = (
        tmp_path
        / "missing-evidence-operational-failure.json"
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert not requested_path.exists()
    assert not failure_path.exists()
    assert "HTTP error:" in result.stderr
    assert (
        "Operational failure evidence written:"
        not in result.stderr
    )


def test_analyze_operational_failure_persistence_error_preserves_http_error(
    monkeypatch,
    tmp_path,
):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=TransportStopReason.TIMEOUT,
        )
    )

    def fail_fetch(*args, **kwargs):
        raise TransportExecutionError(
            (
                "Transport execution failed before a permitted "
                "application response was obtained."
            ),
            evidence=transport,
        )

    def fail_write(*args, **kwargs):
        raise OSError(
            "simulated evidence persistence failure"
        )

    monkeypatch.setattr(
        "php_sentinel.assessment.pipeline.fetch_with_transport",
        fail_fetch,
    )
    monkeypatch.setattr(
        "php_sentinel.cli.write_json_evidence",
        fail_write,
    )

    requested_path = tmp_path / "analysis.json"
    failure_path = (
        tmp_path
        / "analysis-operational-failure.json"
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            "https://example.test/",
            "--json",
            "--evidence-out",
            str(requested_path),
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert not requested_path.exists()
    assert not failure_path.exists()
    assert (
        "Operational failure evidence could not be written:"
        in result.stderr
    )
    assert (
        "simulated evidence persistence failure"
        in result.stderr
    )
    assert "HTTP error:" in result.stderr
    assert "Transport execution failed" in result.stderr
    assert "Traceback" not in result.stderr


def test_scan_body_limit_persistence_error_preserves_http_error(
    monkeypatch,
    tmp_path,
):
    transport = TransportEvidence(
        execution=TransportExecution(
            attempts=1,
            requests_sent=1,
            stop_reason=(
                TransportStopReason.RESPONSE_BODY_LIMIT_EXCEEDED
            ),
        )
    )

    def fail_fetch(*args, **kwargs):
        raise HTTPResponseTooLargeError(
            (
                "Target HTTP response exceeds the maximum "
                "allowed body size."
            ),
            evidence=transport,
        )

    def fail_write(*args, **kwargs):
        raise OSError(
            "simulated evidence persistence failure"
        )

    monkeypatch.setattr(
        "php_sentinel.assessment.pipeline.fetch_with_transport",
        fail_fetch,
    )
    monkeypatch.setattr(
        "php_sentinel.cli.write_json_evidence",
        fail_write,
    )

    requested_path = tmp_path / "scan.json"
    failure_path = (
        tmp_path
        / "scan-operational-failure.json"
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.test/",
            "--json",
            "--evidence-out",
            str(requested_path),
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert not requested_path.exists()
    assert not failure_path.exists()
    assert (
        "Operational failure evidence could not be written:"
        in result.stderr
    )
    assert (
        "simulated evidence persistence failure"
        in result.stderr
    )
    assert "HTTP error:" in result.stderr
    assert "maximum allowed body size" in result.stderr
    assert "Traceback" not in result.stderr


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
