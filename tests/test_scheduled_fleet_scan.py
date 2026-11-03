from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scheduled_fleet_scan.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("scheduled_fleet_scan", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_scheduled_runner_requires_fleet_configuration(monkeypatch, capsys):
    from auditor.cli import EXIT_ERROR

    monkeypatch.delenv("AUDITOR_FLEET_CONFIG", raising=False)
    monkeypatch.delenv("AUDITOR_HISTORY_DIR", raising=False)
    module = _load_script()

    assert module.main() == EXIT_ERROR
    assert "AUDITOR_FLEET_CONFIG" in capsys.readouterr().err


def test_scheduled_runner_imports_project_when_started_outside_repo(tmp_path):
    environment = os.environ.copy()
    environment.pop("AUDITOR_FLEET_CONFIG", None)
    environment.pop("AUDITOR_HISTORY_DIR", None)
    environment.pop("PYTHONPATH", None)

    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "AUDITOR_FLEET_CONFIG" in result.stderr


def test_scheduled_runner_uses_private_lock_and_forwards_configuration(monkeypatch, tmp_path):
    import stat

    from auditor.cli import EXIT_UNKNOWN

    history = tmp_path / "private-history"
    monkeypatch.setenv("AUDITOR_FLEET_CONFIG", str(tmp_path / "fleet.yaml"))
    monkeypatch.setenv("AUDITOR_HISTORY_DIR", str(history))
    monkeypatch.setenv("AWS_PROFILE", "audit-readonly")
    module = _load_script()
    forwarded = []
    monkeypatch.setattr(module, "cli_main", lambda argv: forwarded.extend(argv) or EXIT_UNKNOWN)

    assert module.main() == EXIT_UNKNOWN
    assert forwarded == [
        "fleet-scan",
        "--fleet-config",
        str(tmp_path / "fleet.yaml"),
        "--history-dir",
        str(history),
        "--profile",
        "audit-readonly",
    ]
    assert stat.S_IMODE((history / ".scheduled-fleet-scan.lock").stat().st_mode) == 0o600


def test_scheduled_runner_skips_a_concurrent_scan(monkeypatch, tmp_path, capsys):

    from auditor.cli import EXIT_OK

    history = tmp_path / "private-history"
    history.mkdir(mode=0o700)
    lock_path = history / ".scheduled-fleet-scan.lock"
    lock_path.touch(mode=0o600)
    monkeypatch.setenv("AUDITOR_FLEET_CONFIG", str(tmp_path / "fleet.yaml"))
    monkeypatch.setenv("AUDITOR_HISTORY_DIR", str(history))
    module = _load_script()
    monkeypatch.setattr(module, "cli_main", lambda _argv: (_ for _ in ()).throw(AssertionError("must skip")))
    monkeypatch.setattr(module.fcntl, "flock", lambda *_args: (_ for _ in ()).throw(BlockingIOError()))

    assert module.main() == EXIT_OK
    assert "already running" in capsys.readouterr().err
