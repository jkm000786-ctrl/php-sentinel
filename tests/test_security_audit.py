from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from php_sentinel.intelligence.security_audit import (
    SECURITY_AUDIT_MAX_BYTES,
    SecurityAuditStorageError,
    append_security_audit_event,
    read_security_audit_events,
)
from php_sentinel.models.security_audit import (
    SecurityAuditEvent,
    SecurityAuditEventType,
    SecurityAuditOutcome,
)

NOW = datetime(
    2026,
    10,
    24,
    12,
    0,
    tzinfo=UTC,
)


def event() -> SecurityAuditEvent:
    return SecurityAuditEvent(
        occurred_at=NOW,
        event_type=SecurityAuditEventType.UPDATE_VERIFIED,
        outcome=SecurityAuditOutcome.SUCCEEDED,
        component="intelligence.update",
        operation="verify_staged_bundle",
        policy_id="php-sentinel-default",
        signer_id="policy-signer",
        generation=5,
        trust_state="trusted",
        lifecycle_state="activatable",
        policy_sha256=("a" * 64),
    )


def test_audit_append_and_read_round_trip(
    tmp_path,
):
    path = tmp_path / "audit.jsonl"

    append_security_audit_event(
        path,
        event(),
    )

    append_security_audit_event(
        path,
        event(),
    )

    loaded = read_security_audit_events(path)

    assert len(loaded) == 2
    assert loaded[0].policy_id == "php-sentinel-default"
    assert loaded[1].policy_id == "php-sentinel-default"


def test_missing_audit_log_reads_as_empty(
    tmp_path,
):
    assert read_security_audit_events(tmp_path / "missing.jsonl") == []


def test_audit_writer_rejects_symlink(
    tmp_path,
):
    target = tmp_path / "target.jsonl"
    target.write_text(
        "",
        encoding="utf-8",
    )

    path = tmp_path / "audit.jsonl"
    path.symlink_to(target)

    with pytest.raises(
        SecurityAuditStorageError,
    ):
        append_security_audit_event(
            path,
            event(),
        )


def test_audit_reader_rejects_symlink(
    tmp_path,
):
    target = tmp_path / "target.jsonl"
    target.write_text(
        "",
        encoding="utf-8",
    )

    path = tmp_path / "audit.jsonl"
    path.symlink_to(target)

    with pytest.raises(
        SecurityAuditStorageError,
    ):
        read_security_audit_events(path)


def test_audit_writer_rejects_non_regular_file(
    tmp_path,
):
    path = tmp_path / "audit.jsonl"
    path.mkdir()

    with pytest.raises(
        SecurityAuditStorageError,
    ):
        append_security_audit_event(
            path,
            event(),
        )


def test_audit_reader_rejects_oversized_file(
    tmp_path,
):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"x" * (SECURITY_AUDIT_MAX_BYTES + 1))

    with pytest.raises(
        SecurityAuditStorageError,
        match="maximum allowed size",
    ):
        read_security_audit_events(path)


def test_audit_writer_rejects_file_growth_past_limit(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.security_audit as audit_module

    monkeypatch.setattr(
        audit_module,
        "SECURITY_AUDIT_MAX_BYTES",
        64,
    )

    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"x" * 60)

    with pytest.raises(
        SecurityAuditStorageError,
        match="maximum allowed size",
    ):
        append_security_audit_event(
            path,
            event(),
        )


def test_audit_reader_rejects_malformed_event(
    tmp_path,
):
    path = tmp_path / "audit.jsonl"
    path.write_text(
        "{not-json}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        SecurityAuditStorageError,
        match="malformed or unsupported",
    ):
        read_security_audit_events(path)


def test_audit_model_forbids_free_form_detail():
    with pytest.raises(ValidationError):
        SecurityAuditEvent.model_validate(
            {
                **event().model_dump(mode="json"),
                "detail": "arbitrary operator text",
            }
        )


def test_audit_model_forbids_unstructured_secret_fields():
    with pytest.raises(ValidationError):
        SecurityAuditEvent.model_validate(
            {
                **event().model_dump(mode="json"),
                "private_key": "secret",
            }
        )


def test_audit_file_is_owner_only_when_supported(
    tmp_path,
):
    path = tmp_path / "audit.jsonl"

    append_security_audit_event(
        path,
        event(),
    )

    mode = os.stat(path).st_mode & 0o777

    assert mode & 0o077 == 0


def test_audit_access_fails_closed_without_nofollow_capability(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.security_audit as audit_module

    def deny(*, operation):
        raise audit_module.PlatformSecurityCapabilityError(f"{operation} unavailable")

    monkeypatch.setattr(
        audit_module,
        "require_nofollow_open",
        deny,
    )

    with pytest.raises(
        SecurityAuditStorageError,
        match="unavailable",
    ):
        append_security_audit_event(
            tmp_path / "audit.jsonl",
            event(),
        )


def test_audit_writer_rejects_symlinked_parent_component(
    tmp_path,
):
    real_parent = tmp_path / "real"
    real_parent.mkdir()

    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(
        real_parent,
        target_is_directory=True,
    )

    with pytest.raises(
        SecurityAuditStorageError,
        match="parent path could not be anchored safely",
    ):
        append_security_audit_event(
            linked_parent / "audit.jsonl",
            event(),
        )

    assert not (real_parent / "audit.jsonl").exists()


def test_audit_reader_rejects_symlinked_parent_component(
    tmp_path,
):
    real_parent = tmp_path / "real"
    real_parent.mkdir()

    audit = real_parent / "audit.jsonl"
    append_security_audit_event(
        audit,
        event(),
    )

    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(
        real_parent,
        target_is_directory=True,
    )

    with pytest.raises(
        SecurityAuditStorageError,
        match="parent path could not be anchored safely",
    ):
        read_security_audit_events(
            linked_parent / "audit.jsonl",
        )


def test_missing_audit_parent_reads_as_empty_without_creation(
    tmp_path,
):
    parent = tmp_path / "missing" / "nested"

    assert (
        read_security_audit_events(
            parent / "audit.jsonl",
        )
        == []
    )

    assert not parent.exists()


def test_audit_writer_creates_parent_through_anchored_traversal(
    tmp_path,
):
    path = tmp_path / "one" / "two" / "audit.jsonl"

    append_security_audit_event(
        path,
        event(),
    )

    assert path.is_file()
    assert read_security_audit_events(path) == [event()]


def test_audit_access_fails_closed_without_anchored_traversal(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.intelligence.path_anchor as anchor_module

    def deny(*, operation):
        raise anchor_module.PlatformSecurityCapabilityError(f"{operation} unavailable")

    monkeypatch.setattr(
        anchor_module,
        "require_anchored_directory_traversal",
        deny,
    )

    with pytest.raises(
        SecurityAuditStorageError,
        match="parent path could not be anchored safely",
    ):
        append_security_audit_event(
            tmp_path / "audit.jsonl",
            event(),
        )
