from __future__ import annotations

import runpy
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = str(runpy.run_path(ROOT / "src" / "php_sentinel" / "__init__.py")["__version__"])
PYTHON_VERSIONS = ("3.11", "3.12", "3.13", "3.14")
EXPECTED_COMMANDS = (
    "php-sentinel",
    "php-sentinel-compare",
    "php-sentinel-cve",
    "php-sentinel-intel",
    "php-sentinel-matrix",
    "php-sentinel-update",
)


def run(*args: str) -> None:
    print("+", " ".join(args))
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> None:
    if shutil.which("docker") is None:
        raise SystemExit("Docker is required for the Python compatibility matrix.")

    subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    generated_paths = (
        ROOT / "build",
        ROOT / "src" / "php_sentinel.egg-info",
    )

    try:
        with tempfile.TemporaryDirectory(prefix="php-sentinel-python-matrix-") as tmp:
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

            wheels = sorted(destination.glob("php_sentinel-*.whl"))
            if len(wheels) != 1:
                raise SystemExit(f"Expected one wheel, found {len(wheels)}.")

            wheel = wheels[0]
            for version in PYTHON_VERSIONS:
                image = f"python:{version}-slim"
                command = (
                    f"python --version && "
                    f"python -m pip install --disable-pip-version-check -q /wheel/{wheel.name} && "
                    "python -m pip check && "
                    'python -c \'from importlib.metadata import version; from importlib.resources import files; import php_sentinel; p=files("php_sentinel").joinpath("data/intelligence/php-2026-10-critical.json"); assert version("php-sentinel")=="' + VERSION + '"; assert php_sentinel.__version__=="' + VERSION + '"; assert len(p.read_bytes())>0\' && '
                    + " && ".join(f"{cmd} --version >/dev/null" for cmd in EXPECTED_COMMANDS)
                    + " && "
                    + " && ".join(f"{cmd} --help >/dev/null" for cmd in EXPECTED_COMMANDS)
                )
                run(
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{destination}:/wheel:ro",
                    image,
                    "sh",
                    "-c",
                    command,
                )
                print(f"Python {version}: PASS")

    finally:
        for path in generated_paths:
            if path.exists():
                shutil.rmtree(path)

    print("Python compatibility matrix passed for 3.11, 3.12, 3.13, and 3.14.")


if __name__ == "__main__":
    main()
