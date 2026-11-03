from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_docker_verify_keeps_github_workflows_in_build_context():
    ignored_entries = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    assert ".github" not in ignored_entries


def test_alpine_verify_image_installs_bash_for_shell_tests():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.12-alpine" in dockerfile
    assert "apk add --no-cache bash" in dockerfile


def test_alpine_image_creates_its_non_root_user_with_alpine_tooling():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "adduser -D -u 10001 -h /home/auditor auditor" in dockerfile
