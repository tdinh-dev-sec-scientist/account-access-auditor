from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_build_signed_release_reports_missing_host_dependencies_before_build(tmp_path):
    python_without_runtime_dependencies = tmp_path / "python-without-runtime-dependencies"
    python_without_runtime_dependencies.write_text(
        "#!/bin/sh\n"
        "if [ \"${1:-}\" = \"-c\" ]; then\n"
        "  printf '%s\\n' 'No module named boto3' >&2\n"
        "  exit 1\n"
        "fi\n"
        "exit 97\n",
        encoding="utf-8",
    )
    python_without_runtime_dependencies.chmod(0o755)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' 'Docker was invoked before Python dependency validation' >&2\n"
        "exit 2\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    private_key = tmp_path / "cosign.key"
    public_key = tmp_path / "cosign.pub"
    private_key.touch()
    public_key.touch()
    output_dir = tmp_path / "release-output"
    environment = os.environ.copy()
    environment["PYTHON"] = str(python_without_runtime_dependencies)
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    environment["COSIGN_KEY"] = str(private_key)
    environment["COSIGN_PUBLIC_KEY"] = str(public_key)

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/build_signed_release.sh"), str(output_dir)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 2
    assert "runtime dependencies from requirements.txt" in result.stderr
    assert not output_dir.exists()
