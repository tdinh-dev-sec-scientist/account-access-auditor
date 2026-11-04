"""Packaging metadata stays consistent with the runtime package."""

from __future__ import annotations

import tomllib
from pathlib import Path

from auditor import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_version_matches_runtime_version():
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["version"] == __version__

