from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_github_workflow_keeps_untrusted_pr_permissions_read_only():
    workflow_path = ROOT / ".github/workflows/iac-guardrails.yml"
    raw = workflow_path.read_text()
    workflow = yaml.load(raw, Loader=yaml.BaseLoader)

    assert "pull_request_target" not in raw
    assert workflow["permissions"]["contents"] == "read"
    assert "id-token" not in workflow["permissions"]
    assert "security-events" not in workflow["permissions"]
    assert "security-events: write" not in raw
    assert "AWS_ACCESS_KEY_ID" not in raw
    assert "aws-actions/configure-aws-credentials" not in raw
    assert "persist-credentials: false" in raw
    assert "deploy/gatekeeper/samples/violating-pod.yaml" in raw
    assert "sarif" in raw.lower()
    assert "json" in raw.lower()
    assert "github/codeql-action/upload-sarif" not in raw


def test_sarif_upload_uses_a_separate_trusted_workflow_run():
    workflow_path = ROOT / ".github/workflows/iac-sarif-upload.yml"
    raw = workflow_path.read_text()
    workflow = yaml.load(raw, Loader=yaml.BaseLoader)

    assert workflow["on"]["workflow_run"]["workflows"] == ["IaC guardrails"]
    assert workflow["permissions"]["actions"] == "read"
    assert workflow["permissions"]["security-events"] == "write"
    assert "github.event.workflow_run.event == 'pull_request'" in raw
    assert "head_repository.full_name == github.repository" in raw
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in raw
    assert "github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee" in raw
    assert "checkout@" not in raw


def test_gatekeeper_demo_contains_deny_policy_constraint_and_examples():
    base = ROOT / "deploy/gatekeeper"
    template = yaml.safe_load((base / "template.yaml").read_text())
    constraint = yaml.safe_load((base / "constraint.yaml").read_text())
    clean = yaml.safe_load((base / "samples/clean-pod.yaml").read_text())
    violating = yaml.safe_load((base / "samples/violating-pod.yaml").read_text())

    assert template["apiVersion"] == "templates.gatekeeper.sh/v1"
    assert template["kind"] == "ConstraintTemplate"
    target = template["spec"]["targets"][0]
    assert target["target"] == "admission.k8s.gatekeeper.sh"
    assert "rego" not in target
    assert target["code"][0]["engine"] == "Rego"
    source = target["code"][0]["source"]
    assert source["version"] == "v1"
    rego = source["rego"]
    assert "securityContext.privileged == true" in rego
    assert 'endswith(container.image, ":latest")' in rego
    assert constraint["apiVersion"] == "constraints.gatekeeper.sh/v1beta1"
    assert constraint["spec"]["enforcementAction"] == "deny"
    assert constraint["spec"]["match"]["kinds"][0]["apiGroups"] == [""]
    assert clean["kind"] == violating["kind"] == "Pod"
    assert "@sha256:" in clean["spec"]["containers"][0]["image"]
    assert violating["spec"]["containers"][0]["image"].endswith(":latest")
    assert violating["spec"]["containers"][0]["securityContext"]["privileged"] is True
    assert (base / "README.md").is_file()
    setup = (base / "README.md").read_text()
    assert "--image kindest/node:v1.33.2" in setup
    assert "crd/k8sdenyprivilegedlatest.constraints.gatekeeper.sh" in setup
    assert (ROOT / "scripts/test_gatekeeper_demo.sh").is_file()


def test_gatekeeper_admission_smoke_on_explicit_demo_context():
    if os.environ.get("RUN_GATEKEEPER_DEMO") != "1":
        import pytest

        pytest.skip("set RUN_GATEKEEPER_DEMO=1 to test the named local demo cluster")
    result = subprocess.run(
        [str(ROOT / "scripts/test_gatekeeper_demo.sh")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_gatekeeper_demo_script_refuses_a_nonlocal_cluster(tmp_path):
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    kubectl = stub_bin / "kubectl"
    kubectl.write_text(
        "#!/bin/sh\n"
        'if [ "$*" = "config current-context" ]; then\n'
        "  echo kind-account-access-auditor-demo\n"
        "else\n"
        "  echo https://remote.example.com:6443\n"
        "fi\n"
    )
    kubectl.chmod(0o755)

    result = subprocess.run(
        ["bash", str(ROOT / "scripts/test_gatekeeper_demo.sh")],
        cwd=ROOT,
        env={**os.environ, "PATH": f"{stub_bin}:{os.environ.get('PATH', '')}"},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "must point to a local cluster" in result.stderr


def test_gatekeeper_policy_evaluates_demo_manifests_with_conftest(tmp_path):
    conftest = shutil.which("conftest")
    if not conftest:
        import pytest

        pytest.skip("Conftest is an optional scanner binary")
    base = ROOT / "deploy/gatekeeper"
    template = yaml.safe_load((base / "template.yaml").read_text())
    source = template["spec"]["targets"][0]["code"][0]["source"]
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    policy_dir.joinpath("policy.rego").write_text(source["rego"])

    clean = subprocess.run(
        [
            conftest,
            "test",
            "--all-namespaces",
            "--no-color",
            "--output",
            "json",
            "--parser",
            "yaml",
            "--rego-version",
            "v1",
            "--policy",
            str(policy_dir),
            str(base / "samples/clean-pod.yaml"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    violating = subprocess.run(
        [
            conftest,
            "test",
            "--all-namespaces",
            "--no-color",
            "--output",
            "json",
            "--parser",
            "yaml",
            "--rego-version",
            "v1",
            "--policy",
            str(policy_dir),
            str(base / "samples/violating-pod.yaml"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert violating.returncode == 1, violating.stdout + violating.stderr
