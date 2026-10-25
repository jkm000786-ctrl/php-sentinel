from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DATE_EPOCH = "1700000000"
BUILD_CONSTRAINTS = ROOT / "requirements" / "build-constraints.txt"


def run(*args: str, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(args))
    subprocess.run(args, cwd=ROOT, check=True, env=env)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extracted_hashes(wheel: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            hashes[name] = hashlib.sha256(archive.read(name)).hexdigest()
    return hashes


def main() -> None:
    generated_paths = (
        ROOT / "build",
        ROOT / "src" / "php_sentinel.egg-info",
    )

    try:
        with tempfile.TemporaryDirectory(prefix="php-sentinel-repro-") as tmp:
            base = Path(tmp)
            first = base / "first"
            second = base / "second"
            first.mkdir()
            second.mkdir()

            env = dict(__import__("os").environ)
            env["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
            env["PIP_CONSTRAINT"] = str(BUILD_CONSTRAINTS)

            for destination in (first, second):
                run(
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    ".",
                    "--no-deps",
                    "--wheel-dir",
                    str(destination),
                    env=env,
                )

            first_wheels = sorted(first.glob("*.whl"))
            second_wheels = sorted(second.glob("*.whl"))
            if len(first_wheels) != 1 or len(second_wheels) != 1:
                raise SystemExit("Expected exactly one wheel from each reproducibility build.")

            wheel_a = first_wheels[0]
            wheel_b = second_wheels[0]

            if wheel_a.name != wheel_b.name:
                raise SystemExit("Reproducibility builds produced different wheel names.")

            hash_a = sha256(wheel_a)
            hash_b = sha256(wheel_b)
            print(f"wheel A sha256: {hash_a}")
            print(f"wheel B sha256: {hash_b}")

            if hash_a != hash_b:
                raise SystemExit("Wheel byte hashes differ under fixed SOURCE_DATE_EPOCH.")

            if wheel_a.read_bytes() != wheel_b.read_bytes():
                raise SystemExit("Wheel bytes differ despite matching SHA-256 hashes.")

            with zipfile.ZipFile(wheel_a) as archive_a, zipfile.ZipFile(wheel_b) as archive_b:
                if archive_a.namelist() != archive_b.namelist():
                    raise SystemExit("Wheel archive member ordering differs.")

            if extracted_hashes(wheel_a) != extracted_hashes(wheel_b):
                raise SystemExit("Extracted wheel file contents differ.")

            print(f"Reproducible wheel verified: {wheel_a.name}")
    finally:
        for path in generated_paths:
            if path.exists():
                shutil.rmtree(path)


if __name__ == "__main__":
    main()
