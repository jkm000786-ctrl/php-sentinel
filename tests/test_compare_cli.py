from __future__ import annotations

import pytest

from php_sentinel.compare_cli import (
    COMPARE_REPORT_MAX_BYTES,
    _read_report_bytes,
)


def test_compare_report_reader_rejects_oversized_file(
    tmp_path,
):
    path = tmp_path / "oversized-report.json"

    path.write_bytes(b"x" * (COMPARE_REPORT_MAX_BYTES + 1))

    with pytest.raises(
        ValueError,
        match="maximum allowed size",
    ):
        _read_report_bytes(path)


def test_compare_report_reader_rejects_symlink(
    tmp_path,
):
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")

    path = tmp_path / "report.json"
    path.symlink_to(target)

    with pytest.raises(
        ValueError,
        match="must not be a symbolic link",
    ):
        _read_report_bytes(path)


def test_compare_report_reader_returns_exact_regular_file_bytes(
    tmp_path,
):
    path = tmp_path / "report.json"
    payload = b'{"report":"bounded"}'

    path.write_bytes(payload)

    assert _read_report_bytes(path) == payload


def test_compare_report_reader_rejects_nonpositive_limit(
    tmp_path,
):
    path = tmp_path / "report.json"
    path.write_bytes(b"{}")

    with pytest.raises(
        ValueError,
        match="maximum_bytes must be positive",
    ):
        _read_report_bytes(
            path,
            maximum_bytes=0,
        )


def test_compare_reader_fails_closed_without_nofollow_capability(
    tmp_path,
    monkeypatch,
):
    import php_sentinel.compare_cli as compare_module
    from php_sentinel.intelligence.platform_security import (
        PlatformSecurityCapabilityError,
    )

    path = tmp_path / "report.json"
    path.write_text("{}", encoding="utf-8")

    def deny(
        *,
        operation,
    ):
        raise PlatformSecurityCapabilityError(f"{operation} unavailable.")

    monkeypatch.setattr(
        compare_module,
        "require_nofollow_open",
        deny,
    )

    with pytest.raises(
        ValueError,
        match="cannot provide no-follow open semantics",
    ):
        compare_module._read_report_bytes(path)
