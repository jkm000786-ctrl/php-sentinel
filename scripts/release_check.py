from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_INTELLIGENCE = "php_sentinel/data/intelligence/php-2026-10-critical.json"
EXPECTED_COMMANDS = (
    "php-sentinel",
    "php-sentinel-compare",
    "php-sentinel-cve",
    "php-sentinel-intel",
    "php-sentinel-matrix",
    "php-sentinel-update",
)


def run(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(args))
    return subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=capture,
    )


def require_clean_tree() -> None:
    result = run("git", "status", "--porcelain", capture=True)
    if result.stdout.strip():
        raise SystemExit("Release check requires a clean Git working tree.")


def load_project_scripts() -> dict[str, str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
    if tuple(sorted(scripts)) != tuple(sorted(EXPECTED_COMMANDS)):
        raise SystemExit(
            f"Unexpected console scripts: {sorted(scripts)}; expected {sorted(EXPECTED_COMMANDS)}"
        )
    return scripts


def canonical_version() -> str:
    result = run(
        sys.executable,
        "-c",
        "from php_sentinel import __version__; print(__version__)",
        capture=True,
    )
    return result.stdout.strip()


def verify_cli_versions(version: str) -> None:
    for command in EXPECTED_COMMANDS:
        result = run(command, "--version", capture=True)
        observed = result.stdout.strip()
        if observed != version:
            raise SystemExit(f"{command} reported {observed!r}; expected {version!r}.")


def build_and_verify_wheel(version: str) -> None:
    generated_paths = (
        ROOT / "build",
        ROOT / "src" / "php_sentinel.egg-info",
    )

    try:
        with tempfile.TemporaryDirectory(prefix="php-sentinel-release-") as tmp:
            destination = Path(tmp)
            run(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--wheel-dir",
                str(destination),
            )

            wheels = sorted(destination.glob("*.whl"))
            if len(wheels) != 1:
                raise SystemExit(f"Expected exactly one wheel, found {len(wheels)}.")

            wheel = wheels[0]
            expected_name = f"php_sentinel-{version}-py3-none-any.whl"
            if wheel.name != expected_name:
                raise SystemExit(f"Wheel name {wheel.name!r} does not match {expected_name!r}.")

            with ZipFile(wheel) as archive:
                names = set(archive.namelist())
                if EXPECTED_INTELLIGENCE not in names:
                    raise SystemExit("Bundled intelligence file is missing from the wheel.")

                metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
                entry_name = next(
                    name for name in names if name.endswith(".dist-info/entry_points.txt")
                )

                metadata = archive.read(metadata_name).decode("utf-8")
                entry_points = archive.read(entry_name).decode("utf-8")

            if f"Version: {version}" not in metadata:
                raise SystemExit("Wheel metadata version does not match canonical version.")
            if "Description-Content-Type: text/markdown" not in metadata:
                raise SystemExit("Wheel metadata is missing Markdown long-description type.")
            if "Author: Jahangir Karim" not in metadata:
                raise SystemExit("Wheel metadata is missing the expected author identity.")
            if "License-Expression: Apache-2.0" not in metadata:
                raise SystemExit("Wheel metadata is missing the Apache-2.0 license expression.")
            if "License-File: LICENSE" not in metadata:
                raise SystemExit("Wheel metadata is missing the LICENSE file declaration.")
            license_members = [
                name for name in names if name.endswith(".dist-info/licenses/LICENSE")
            ]
            if len(license_members) != 1:
                raise SystemExit("Wheel must contain exactly one packaged LICENSE file.")

            for command in EXPECTED_COMMANDS:
                if f"{command} = " not in entry_points:
                    raise SystemExit(f"Wheel is missing console entry point {command!r}.")

            print(f"Verified wheel: {wheel.name}")
    finally:
        for path in generated_paths:
            if path.exists():
                shutil.rmtree(path)


def verify_fresh_install(version: str) -> None:
    generated_paths = (
        ROOT / "build",
        ROOT / "src" / "php_sentinel.egg-info",
    )

    try:
        with tempfile.TemporaryDirectory(prefix="php-sentinel-fresh-install-") as tmp:
            base = Path(tmp)
            wheel_dir = base / "wheel"
            venv_dir = base / "venv"
            wheel_dir.mkdir()

            run(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--wheel-dir",
                str(wheel_dir),
            )

            wheels = sorted(wheel_dir.glob("*.whl"))
            if len(wheels) != 1:
                raise SystemExit(f"Expected one wheel for fresh install, found {len(wheels)}.")

            wheel = wheels[0]
            run(sys.executable, "-m", "venv", str(venv_dir))
            fresh_python = venv_dir / "bin" / "python"
            fresh_bin = venv_dir / "bin"

            run(str(fresh_python), "-m", "pip", "install", str(wheel))
            run(str(fresh_python), "-m", "pip", "check")

            result = run(
                str(fresh_python),
                "-c",
                'from importlib.metadata import version; from importlib.resources import files; import php_sentinel; p=files("php_sentinel").joinpath("data/intelligence/php-2026-10-critical.json"); print(version("php-sentinel")); print(php_sentinel.__version__); print(len(p.read_bytes()))',
                capture=True,
            )
            lines = result.stdout.strip().splitlines()
            if len(lines) != 3 or lines[0] != version or lines[1] != version:
                raise SystemExit("Fresh-install package version identity is inconsistent.")
            if int(lines[2]) <= 0:
                raise SystemExit("Fresh-install bundled intelligence resource is empty.")

            for command in EXPECTED_COMMANDS:
                executable = fresh_bin / command
                observed = run(str(executable), "--version", capture=True).stdout.strip()
                if observed != version:
                    raise SystemExit(
                        f"Fresh-install {command} reported {observed!r}; expected {version!r}."
                    )
                run(str(executable), "--help", capture=True)

            print(f"Verified fresh wheel installation for PHP Sentinel {version}.")
    finally:
        for path in generated_paths:
            if path.exists():
                shutil.rmtree(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PHP Sentinel release-readiness checks.")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Permit uncommitted changes while validating a development tree.",
    )
    args = parser.parse_args()

    if not args.allow_dirty:
        require_clean_tree()

    load_project_scripts()
    run("ruff", "check", "src", "tests", "scripts")
    run("pytest", "-q")
    run("git", "diff", "--check")

    version = canonical_version()
    verify_cli_versions(version)
    build_and_verify_wheel(version)
    verify_fresh_install(version)

    print(f"Release checks passed for PHP Sentinel {version}.")


if __name__ == "__main__":
    main()
