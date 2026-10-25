from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SDIST = "php_sentinel-0.1.0.tar.gz"
REQUIRED_MEMBERS = {
    "README.md",
    "SECURITY.md",
    "RELEASE.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "requirements/build-constraints.txt",
    "src/php_sentinel/__init__.py",
    "src/php_sentinel/data/intelligence/php-2026-10-critical.json",
}
BUILD_TOOLS = ("build==1.6.1", "setuptools==84.2.1", "wheel==0.48.0", "packaging==26.3")
COMMANDS = (
    "php-sentinel",
    "php-sentinel-compare",
    "php-sentinel-cve",
    "php-sentinel-intel",
    "php-sentinel-matrix",
    "php-sentinel-update",
)


def run(*args: str, cwd: Path = ROOT) -> None:
    print("+", " ".join(args))
    subprocess.run(args, cwd=cwd, check=True)


def main() -> None:
    generated = (ROOT / "build", ROOT / "dist", ROOT / "src" / "php_sentinel.egg-info")
    try:
        with tempfile.TemporaryDirectory(prefix="php-sentinel-sdist-") as tmp:
            base = Path(tmp)
            build_venv = base / "build-venv"
            install_venv = base / "install-venv"
            dist = base / "dist"
            extracted = base / "extracted"
            rebuilt = base / "rebuilt"
            dist.mkdir()
            extracted.mkdir()
            rebuilt.mkdir()

            run(sys.executable, "-m", "venv", str(build_venv))
            build_python = build_venv / "bin" / "python"
            run(
                str(build_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "-q",
                *BUILD_TOOLS,
            )
            run(
                str(build_python),
                "-m",
                "build",
                "--no-isolation",
                "--sdist",
                "--outdir",
                str(dist),
                ".",
            )

            sdist = dist / EXPECTED_SDIST
            if not sdist.is_file():
                raise SystemExit(f"Expected sdist not found: {sdist.name}")

            with tarfile.open(sdist, "r:gz") as archive:
                names = archive.getnames()
                prefix = "php_sentinel-0.1.0/"
                relative = {name.removeprefix(prefix) for name in names if name.startswith(prefix)}
                missing = sorted(REQUIRED_MEMBERS - relative)
                if missing:
                    raise SystemExit("Missing required sdist members: " + ", ".join(missing))
                archive.extractall(extracted, filter="data")

            root = extracted / "php_sentinel-0.1.0"
            run(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                str(root),
                "--no-deps",
                "--build-constraint",
                str(ROOT / "requirements" / "build-constraints.txt"),
                "--wheel-dir",
                str(rebuilt),
            )

            wheels = sorted(rebuilt.glob("php_sentinel-0.1.0-py3-none-any.whl"))
            if len(wheels) != 1:
                raise SystemExit("Expected exactly one wheel rebuilt from the sdist.")

            run(sys.executable, "-m", "venv", str(install_venv))
            install_python = install_venv / "bin" / "python"
            run(
                str(install_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                str(sdist),
            )
            run(str(install_python), "-m", "pip", "check")
            run(
                str(install_python),
                "-c",
                'from importlib.metadata import version; from importlib.resources import files; import php_sentinel; p=files("php_sentinel").joinpath("data/intelligence/php-2026-10-critical.json"); assert version("php-sentinel")=="0.1.0"; assert php_sentinel.__version__=="0.1.0"; assert len(p.read_bytes())>0',
            )

            bindir = install_venv / "bin"
            for command in COMMANDS:
                run(str(bindir / command), "--version")
                run(str(bindir / command), "--help")

            print(f"Verified sdist: {sdist.name}")
    finally:
        for path in generated:
            if path.exists():
                shutil.rmtree(path)


if __name__ == "__main__":
    main()
