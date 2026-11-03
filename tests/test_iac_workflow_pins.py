from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFTEST_ASSET = "conftest_0.71.1_Linux_x86_64.tar.gz"


def test_pinned_conftest_download_names_match_published_linux_asset():
    workflow_paths = (
        REPO_ROOT / ".github" / "workflows" / "ci.yml",
        REPO_ROOT / ".github" / "workflows" / "iac-guardrails.yml",
    )

    for workflow_path in workflow_paths:
        workflow = workflow_path.read_text(encoding="utf-8")
        assert CONFTEST_ASSET in workflow
        assert f"grep '{CONFTEST_ASSET}$'" in workflow
        assert "conftest_0.71.1_Linux_amd64.tar.gz" not in workflow


def test_ci_pins_the_same_ruff_version_as_the_dev_extra():
    ci_workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    project_config = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "pip install ruff==0.17.3" in ci_workflow
    assert '"ruff==0.17.3"' in project_config
