from __future__ import annotations

from typer.testing import CliRunner

import php_sentinel.intelligence_update_cli as update_cli

runner = CliRunner()


def test_operational_commands_expose_optional_audit_log():
    for command in (
        "stage",
        "verify",
        "promote",
        "source-stage",
        "source-promote",
        "source-activate",
        "registry-activate",
    ):
        result = runner.invoke(
            update_cli.app,
            [
                command,
                "--help",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "--audit-log" in result.output


def test_stage_cli_forwards_audit_log(
    tmp_path,
    monkeypatch,
):
    captured = {}

    def fake_stage_remote_bundle(**kwargs):
        captured.update(kwargs)

        class Metadata:
            def model_dump(self, *, mode):
                assert mode == "json"
                return {"ok": True}

        return Metadata()

    monkeypatch.setattr(
        update_cli,
        "stage_remote_bundle",
        fake_stage_remote_bundle,
    )

    audit_path = tmp_path / "audit.jsonl"

    result = runner.invoke(
        update_cli.app,
        [
            "stage",
            "--policy-url",
            "https://updates.example.test/policy.json",
            "--manifest-url",
            "https://updates.example.test/manifest.json",
            "--staging-dir",
            str(tmp_path / "stage"),
            "--audit-log",
            str(audit_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["security_audit_path"] == audit_path


def test_registry_activate_cli_forwards_audit_log(
    tmp_path,
    monkeypatch,
):
    captured = {}

    class State:
        value = "trusted"

    class Lifecycle:
        generation = 7
        state = State()

    class Trust:
        registry_sha256 = "a" * 64
        signer_id = "registry-signer"
        state = State()

    class Verified:
        trust = Trust()
        lifecycle = Lifecycle()

    def fake_activate_signed_source_registry(**kwargs):
        captured.update(kwargs)
        return Verified()

    monkeypatch.setattr(
        update_cli,
        "activate_signed_source_registry",
        fake_activate_signed_source_registry,
    )

    audit_path = tmp_path / "audit.jsonl"

    result = runner.invoke(
        update_cli.app,
        [
            "registry-activate",
            "--registry",
            str(tmp_path / "registry.json"),
            "--registry-manifest",
            str(tmp_path / "manifest.json"),
            "--registry-trust-store",
            str(tmp_path / "trust.json"),
            "--registry-state",
            str(tmp_path / "state.json"),
            "--audit-log",
            str(audit_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["security_audit_path"] == audit_path
