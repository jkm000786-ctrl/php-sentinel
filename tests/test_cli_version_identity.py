from __future__ import annotations

import subprocess

import pytest

from php_sentinel import __version__


@pytest.mark.parametrize(
    "command",
    (
        "php-sentinel",
        "php-sentinel-matrix",
        "php-sentinel-cve",
        "php-sentinel-compare",
        "php-sentinel-intel",
        "php-sentinel-update",
    ),
)
def test_installed_cli_reports_canonical_package_version(command):
    result = subprocess.run(
        [command, "--version"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == __version__
    assert result.stderr == ""
