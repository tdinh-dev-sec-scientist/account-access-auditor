#!/usr/bin/env python3
"""Host-scheduler entry point for a read-only fleet scan."""

from __future__ import annotations

import fcntl
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auditor.cli import EXIT_ERROR, EXIT_OK  # noqa: E402
from auditor.cli import main as cli_main


def main() -> int:
    fleet_config = os.environ.get("AUDITOR_FLEET_CONFIG")
    history_value = os.environ.get("AUDITOR_HISTORY_DIR")
    if not fleet_config or not history_value:
        print("Set AUDITOR_FLEET_CONFIG and AUDITOR_HISTORY_DIR before scheduling scans.", file=sys.stderr)
        return EXIT_ERROR

    history_directory = Path(history_value).expanduser()
    if history_directory.is_symlink():
        print("History directory must not be a symbolic link.", file=sys.stderr)
        return EXIT_ERROR
    try:
        previous_umask = os.umask(0o077)
        try:
            history_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        finally:
            os.umask(previous_umask)
        if stat.S_IMODE(history_directory.stat().st_mode) & 0o077:
            print("History directory permissions must be private (0700).", file=sys.stderr)
            return EXIT_ERROR
        lock_path = history_directory / ".scheduled-fleet-scan.lock"
        if lock_path.is_symlink():
            print("Scheduler lock must not be a symbolic link.", file=sys.stderr)
            return EXIT_ERROR
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            if stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o077:
                print("Scheduler lock permissions must be private (0600).", file=sys.stderr)
                return EXIT_ERROR
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("A scheduled fleet scan is already running; skipping this invocation.", file=sys.stderr)
                return EXIT_OK

            arguments = [
                "fleet-scan",
                "--fleet-config",
                fleet_config,
                "--history-dir",
                str(history_directory),
            ]
            profile = os.environ.get("AWS_PROFILE")
            if profile:
                arguments.extend(["--profile", profile])
            app_config = os.environ.get("AUDITOR_APP_CONFIG")
            if app_config:
                arguments.extend(["--config", app_config])
            fail_on = os.environ.get("AUDITOR_FAIL_ON")
            if fail_on:
                arguments.extend(["--fail-on", fail_on])
            return cli_main(arguments)
        finally:
            os.close(descriptor)
    except OSError as exc:
        print(
            f"Scheduled fleet scan could not prepare its private lock ({exc.__class__.__name__}).",
            file=sys.stderr,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
