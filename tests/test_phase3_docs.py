from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase3_status_separates_local_implementation_from_live_stage_acceptance():
    status = (ROOT / "docs/phase3-status.md").read_text(encoding="utf-8")
    normalized_status = " ".join(status.split())

    assert "No live stage gate has passed" in normalized_status
    for stage in ("Stage 1", "Stage 2", "Stage 3", "Stage 4"):
        assert stage in status
    assert "implementation" in status.lower()
    assert "acceptance" in status.lower()
    assert "read-only" in status.lower()


def test_phase3_cost_record_never_invents_owner_values_or_actual_spend():
    costs = (ROOT / "docs/costs.md").read_text(encoding="utf-8")

    assert "AWS Pricing Calculator" in costs
    assert "Not recorded" in costs
    assert "AWS actual spend" in costs
    assert "provider" in costs.lower()
    assert "disabled by default" in costs


def test_phase3_runbook_and_threat_model_cover_the_publication_boundary_and_kill_switch():
    runbook = (ROOT / "docs/operations-runbook.md").read_text(encoding="utf-8")
    threat = (ROOT / "docs/threat-model.md").read_text(encoding="utf-8")

    assert "Phase 3 live operations" in runbook
    assert "static mode" in runbook.lower()
    assert "not a hard spend limit" in runbook.lower()
    assert "public-results" in threat
    assert "publisher" in threat.lower()
    assert "Rin" in threat


def test_phase3_execution_plan_and_runbook_match_fargate_and_remote_state_design():
    plan = (ROOT / "docs/superpowers/plans/2026-11-03-phase3-live-demo.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs/operations-runbook.md").read_text(encoding="utf-8")

    assert "phase3/scan_task.py" in plan
    assert "ECS Fargate" in plan
    assert "phase3.scan_worker.lambda_handler" not in plan
    assert "local state backend by default" not in runbook
    assert "infra/phase3/demo-account" in runbook
    assert "Phase 3 Terraform" in runbook
    assert "must require a reviewer" in runbook.lower()
    assert "PHASE3_TF_STATE_BUCKET" in runbook


def test_phase3_oidc_bootstrap_guide_limits_initial_terraform_identity():
    guide = (ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8")

    assert "Phase3DemoBootstrapPlan" in guide
    assert "Phase3DemoBootstrapApply" in guide
    assert "OrganizationAccountAccessRole" in guide
    assert "phase3-demo-bootstrap-plan" in guide
    assert "phase3-demo-bootstrap-apply" in guide
    assert "demo-bootstrap-plan.json" in guide
    assert "demo-bootstrap-apply.json" in guide
    assert "refs/heads/main" in guide
