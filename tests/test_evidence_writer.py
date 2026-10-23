import json

from php_sentinel.evidence.writer import write_json_evidence
from php_sentinel.models.validation import ValidationReport


def test_json_evidence_writer(tmp_path):
    report = ValidationReport(
        target="http://127.0.0.1:8080/",
        authorized=True,
    )

    output = write_json_evidence(
        report,
        tmp_path / "report.json",
    )

    data = json.loads(output.read_text())

    assert data["target"] == "http://127.0.0.1:8080/"
    assert data["authorized"] is True
