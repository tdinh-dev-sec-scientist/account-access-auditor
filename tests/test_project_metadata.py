"""Packaging metadata stays consistent with the runtime package."""

from __future__ import annotations

import tomllib
from pathlib import Path

from auditor import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_version_matches_runtime_version():
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["version"] == __version__


def test_license_names_a_copyright_holder():
    first_lines = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8").splitlines()[:3]

    copyright_line = next(line for line in first_lines if line.startswith("Copyright"))
    assert copyright_line.strip() != "Copyright (c) 2026"
