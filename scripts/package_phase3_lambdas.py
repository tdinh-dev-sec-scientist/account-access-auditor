#!/usr/bin/env python3
"""Package Python 3.12 x86_64 Lambda handlers with pinned runtime dependencies."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "build" / "phase3" / "lambda.zip"
PACKAGES = ("auditor", "phase3")


def build_lambda_package(output: Path = DEFAULT_OUTPUT) -> Path:
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("Lambda packaging requires Python 3.12; use the pinned CI/runtime interpreter.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase3-lambda-", dir=output.parent) as temp_dir:
        staging = Path(temp_dir) / "bundle"
        staging.mkdir()
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-compile",
                "--only-binary=:all:",
                "--platform=manylinux2014_x86_64",
                "--implementation=cp",
                "--python-version=3.12",
                "--abi=cp312",
                "--target",
                str(staging),
                "-r",
                str(ROOT / "requirements-phase3-lambda.txt"),
            ],
            check=True,
            cwd=ROOT,
        )
        for package in PACKAGES:
            shutil.copytree(
                ROOT / package,
                staging / package,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
        temp_zip = output.with_suffix(".zip.tmp")
        with zipfile.ZipFile(temp_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(staging.rglob("*")):
                if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                    continue
                name = path.relative_to(staging).as_posix()
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                archive.writestr(info, path.read_bytes())
        os.replace(temp_zip, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = build_lambda_package(args.output.resolve())
    print(f"Built deterministic Lambda bundle at {result}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc)) from None
