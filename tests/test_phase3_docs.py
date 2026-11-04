import json
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
    assert "No profile with access to the Phase 3 public-results store is configured" in normalized_status


def test_phase3_status_records_unavailable_aws_identity_and_pending_policy_review():
    status = " ".join((ROOT / "docs/phase3-status.md").read_text(encoding="utf-8").split())

    assert "`audit-readonly` profile can obtain an identity but AWS denies `iam:ListRoles`" in status
    assert "`default` profile resolves to account root" in status
    assert "no actual aws role policies were captured" in status.lower()
    assert "org and control-plane plan/apply roles separate and pending" in status.lower()
    assert "version-3 role manifest" in status.lower()


def test_role_scope_manifest_keeps_plan_and_apply_roles_separately_pending():
    manifest = json.loads((ROOT / "docs/evidence/phase3-role-scope.json").read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 3
    assert set(manifest["roles"]) == {"org", "control-plane"}
    for phases in manifest["roles"].values():
        assert set(phases) == {"plan", "apply"}
        for record in phases.values():
            assert record["status"] == "pending"
            assert record["role_arn_sha256"] is None
            assert record["evidence"] == []
            assert record["evidence_sha256"] == {}
            assert record["source_evidence_sha256"] == {}


def test_role_capture_guide_uses_non_root_read_only_capture_and_keeps_manifest_pending():
    guide = (ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8")
    normalized_guide = " ".join(guide.split())

    assert "scripts/capture_phase3_role_evidence.py" in guide
    assert "scripts/verify_phase3_role_capture.py" in guide
    assert "SHA-256 fingerprint of the exact role ARN" in guide
    assert "exact deterministic redaction" in normalized_guide
    assert "named non-root profile" in guide
    assert "iam:GetRole" in guide
    assert "iam:GetPolicyVersion" in guide
    assert "never changes the manifest's review status" in normalized_guide
    assert "resource and policy names" in normalized_guide
    assert "public GitHub OIDC claims" in normalized_guide
    assert "Exact policy names and values stay in owner-only source files" in normalized_guide


def test_stage_acceptance_guide_lists_required_evidence_and_digest_review():
    guide = " ".join((ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8").split())

    for artifact in (
        "stage1/scheduled-scan-results.json",
        "stage1/drift-review.json",
        "stage1/read-only-role-review.json",
        "stage2/redaction-test-results.json",
        "stage2/publisher-failure.json",
        "stage2/public-api-methods.json",
        "stage3/transport-security.json",
        "stage3/external-tls-scan.json",
        "stage3/privacy-accessibility.json",
        "stage3/rin-evaluation.json",
        "stage3/quota-fallbacks.json",
        "stage3/failure-banners.json",
        "stage3/transport-security.json",
        "stage3/rin-evaluation.json",
        "stage3/quota-fallbacks.json",
        "stage3/failure-banners.json",
        "stage4/budget-cutoff.json",
        "stage4/kill-switch-recovery.json",
        "stage4/load-resilience.json",
        "stage4/actual-monthly-cost.json",
        "stage4/launch-evidence.json",
    ):
        assert artifact in guide
    assert "evidence_sha256" in guide
    assert "not a test fixture or placeholder" in guide
    assert "changing a file after review blocks the stage" in guide
    assert "Generic `checked: true` files do not satisfy these schemas" in guide
    assert "match the configured ARN and version exactly" in guide
    assert "actual AWS and provider costs against their separate budgets" in guide
    assert "browser-network and accessibility report digests" in guide
    assert "Generic `checked: true` files do not satisfy these schemas" in guide
    assert "match the configured ARN and version exactly" in guide


def test_readme_walkthrough_gif_is_fixture_backed_and_reproducible():
    status = " ".join((ROOT / "docs/phase3-status.md").read_text(encoding="utf-8").split())
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "README now gives visitors a short console walkthrough" in status
    assert "scripts/render_console_gif.py" in status
    assert "not a live AWS account" in status
    assert "docs/images/console-walkthrough.gif" in readme
    assert (ROOT / "docs/images/console-walkthrough.gif").read_bytes()[:6] in (b"GIF87a", b"GIF89a")
    assert (ROOT / "scripts/render_console_gif.py").is_file()


def test_stage_three_guardrail_review_criteria_remain_pending_until_structured_evidence_exists():
    manifest = json.loads((ROOT / "docs/evidence/phase3-stage-acceptance.json").read_text(encoding="utf-8"))
    stage3 = manifest["stages"]["stage3"]

    assert manifest["schema_version"] == 3
    assert stage3["status"] == "pending"
    assert stage3["criteria"]["published_guardrail_policy_review"] is False
    assert stage3["criteria"]["bedrock_invocation_logging_review"] is False
    assert stage3["evidence"] == []
    assert stage3["evidence_sha256"] == {}


def test_stage_three_review_requires_digest_bound_captures_and_short_prompt_retention():
    bootstrap = (ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8")
    status = (ROOT / "docs/phase3-status.md").read_text(encoding="utf-8")

    for artifact in (
        "stage3/guardrail-configuration.json",
        "stage3/guardrail-evaluation.json",
        "stage3/bedrock-logging-settings.json",
        "stage3/external-provider-logging-settings.json",
    ):
        assert artifact in bootstrap
        assert artifact in status
    assert "matching SHA-256" in bootstrap
    assert "capped at 30" in bootstrap
    assert "expected/observed action" in bootstrap
    assert "Review summaries must" in bootstrap


def test_phase3_cost_record_never_invents_owner_values_or_actual_spend():
    costs = (ROOT / "docs/costs.md").read_text(encoding="utf-8")

    assert "AWS Pricing Calculator" in costs
    assert "Not recorded" in costs
    assert "AWS actual spend" in costs
    assert "provider" in costs.lower()
    assert "disabled by default" in costs
    assert "two Bedrock Guardrail evaluations" in costs


def test_phase3_runbook_and_threat_model_cover_the_publication_boundary_and_kill_switch():
    runbook = (ROOT / "docs/operations-runbook.md").read_text(encoding="utf-8")
    threat = (ROOT / "docs/threat-model.md").read_text(encoding="utf-8")

    assert "Phase 3 live operations" in runbook
    assert "static mode" in runbook.lower()
    assert "not a hard spend limit" in runbook.lower()
    assert "public-results" in threat
    assert "publisher" in threat.lower()
    assert "Rin" in threat
    assert "Bedrock Guardrail" in threat
    assert "bedrock:ApplyGuardrail" in threat
    assert "output Guardrail" in runbook


def test_phase3_runbook_matches_fargate_and_remote_state_design():
    runbook = (ROOT / "docs/operations-runbook.md").read_text(encoding="utf-8")

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
    assert "Rin Bedrock Guardrail" in guide
    assert "bedrock:ApplyGuardrail" in guide
    assert "source=INPUT" in guide and "source=OUTPUT" in guide
