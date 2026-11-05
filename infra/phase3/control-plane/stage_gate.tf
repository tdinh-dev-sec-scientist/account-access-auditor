locals {
  phase3_stage_acceptance   = jsondecode(file("${path.module}/../../../docs/evidence/phase3-stage-acceptance.json"))
  phase3_stages             = try(local.phase3_stage_acceptance.stages, {})
  phase3_stage1             = try(local.phase3_stages.stage1, {})
  phase3_stage2             = try(local.phase3_stages.stage2, {})
  phase3_stage3             = try(local.phase3_stages.stage3, {})
  phase3_stage_schema_valid = try(local.phase3_stage_acceptance.schema_version == 3, false)
  phase3_stage3_guardrail_review = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/guardrail-policy-review.json"
  )), {})
  phase3_stage3_logging_review = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/bedrock-logging-review.json"
  )), {})
  phase3_stage3_guardrail_configuration = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/guardrail-configuration.json"
  )), {})
  phase3_stage3_guardrail_evaluation = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/guardrail-evaluation.json"
  )), {})
  phase3_stage3_bedrock_logging = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/bedrock-logging-settings.json"
  )), {})
  phase3_stage3_external_logging = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/external-provider-logging-settings.json"
  )), {})
  phase3_stage3_required_evaluation_categories = toset([
    "input_prompt_attack",
    "input_sensitive_data",
    "input_off_scope",
    "output_prompt_attack",
    "output_sensitive_data",
    "output_off_scope",
    "safe_in_scope",
  ])

  phase3_stage1_scans = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage1/scheduled-scan-results.json"
  )), {})
  phase3_stage1_schedule_log = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage1/schedule-execution-log.json"
  )), {})
  phase3_stage1_drift = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage1/drift-review.json"
  )), {})
  phase3_stage1_role = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage1/read-only-role-review.json"
  )), {})
  phase3_stage1_evidence_valid = try(
    length(keys(local.phase3_stage1_scans)) == 9 &&
    local.phase3_stage1_scans.schema_version == 1 &&
    local.phase3_stage1_scans.reviewed_by == local.phase3_stage1.reviewed_by &&
    local.phase3_stage1_scans.reviewed_at == local.phase3_stage1.reviewed_at &&
    local.phase3_stage1_scans.target_account_label == "demo-account" &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage1_scans.target_account_id_sha256)) &&
    local.phase3_stage1_scans.target_account_id_sha256 == sha256(var.demo_account_id) &&
    local.phase3_stage1_scans.schedule_execution_log_evidence_path == "stage1/schedule-execution-log.json" &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage1_scans.schedule_execution_log_sha256)) &&
    local.phase3_stage1_scans.schedule_execution_log_sha256 == filesha256("${path.module}/../../../docs/evidence/stage1/schedule-execution-log.json") &&
    local.phase3_stage1_scans.consecutive_schedule_runs == true &&
    length(local.phase3_stage1_scans.scans) == 2 &&
    alltrue([
      for run in local.phase3_stage1_scans.scans :
      length(keys(run)) == 6 && run.trigger == "scheduled" && run.status == "complete" &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", run.scan_run_id)) &&
      can(regex("^[a-f0-9]{64}$", run.snapshot_sha256)) &&
      timecmp(run.started_at, run.completed_at) <= 0
    ]) &&
    timecmp(local.phase3_stage1_scans.scans[0].completed_at, local.phase3_stage1_scans.scans[1].started_at) < 0 &&
    local.phase3_stage1_scans.scans[0].scan_run_id != local.phase3_stage1_scans.scans[1].scan_run_id &&
    length(keys(local.phase3_stage1_schedule_log)) == 7 &&
    local.phase3_stage1_schedule_log.schema_version == 1 &&
    local.phase3_stage1_schedule_log.reviewed_by == local.phase3_stage1.reviewed_by &&
    local.phase3_stage1_schedule_log.reviewed_at == local.phase3_stage1.reviewed_at &&
    local.phase3_stage1_schedule_log.complete_export == true &&
    timecmp(local.phase3_stage1_schedule_log.export_window_start, local.phase3_stage1_scans.scans[0].started_at) <= 0 &&
    timecmp(local.phase3_stage1_schedule_log.export_window_end, local.phase3_stage1_scans.scans[1].completed_at) >= 0 &&
    length(local.phase3_stage1_schedule_log.scheduled_executions) == 2 &&
    alltrue([
      for index, execution in local.phase3_stage1_schedule_log.scheduled_executions :
      length(keys(execution)) == 6 && execution.scan_run_id == local.phase3_stage1_scans.scans[index].scan_run_id &&
      timecmp(execution.workflow_started_at, execution.scheduled_at) >= 0 &&
      timecmp(execution.workflow_started_at, timeadd(execution.scheduled_at, "1h")) <= 0 &&
      timecmp(execution.scan_started_at, execution.workflow_started_at) >= 0 &&
      timecmp(execution.scan_started_at, local.phase3_stage1_scans.scans[index].started_at) == 0 &&
      execution.status == "complete" && execution.snapshot_sha256 == local.phase3_stage1_scans.scans[index].snapshot_sha256
    ]) &&
    timecmp(
      timeadd(local.phase3_stage1_schedule_log.scheduled_executions[0].scheduled_at, "6h"),
      local.phase3_stage1_schedule_log.scheduled_executions[1].scheduled_at
    ) == 0 &&
    length(keys(local.phase3_stage1_drift)) == 8 &&
    local.phase3_stage1_drift.schema_version == 1 &&
    local.phase3_stage1_drift.reviewed_by == local.phase3_stage1.reviewed_by &&
    local.phase3_stage1_drift.reviewed_at == local.phase3_stage1.reviewed_at &&
    local.phase3_stage1_drift.previous_scan_run_id == local.phase3_stage1_scans.scans[0].scan_run_id &&
    local.phase3_stage1_drift.current_scan_run_id == local.phase3_stage1_scans.scans[1].scan_run_id &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage1_drift.terraform_change_sha256)) &&
    length(local.phase3_stage1_drift.new_finding_ids) > 0 &&
    length(distinct(local.phase3_stage1_drift.new_finding_ids)) == length(local.phase3_stage1_drift.new_finding_ids) &&
    alltrue([for finding_id in local.phase3_stage1_drift.new_finding_ids : trimspace(finding_id) != ""]) &&
    length(local.phase3_stage1_drift.resolved_finding_ids) > 0 &&
    length(distinct(local.phase3_stage1_drift.resolved_finding_ids)) == length(local.phase3_stage1_drift.resolved_finding_ids) &&
    alltrue([for finding_id in local.phase3_stage1_drift.resolved_finding_ids : trimspace(finding_id) != ""]) &&
    length(keys(local.phase3_stage1_role)) == 6 &&
    local.phase3_stage1_role.schema_version == 1 &&
    local.phase3_stage1_role.reviewed_by == local.phase3_stage1.reviewed_by &&
    local.phase3_stage1_role.reviewed_at == local.phase3_stage1.reviewed_at &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage1_role.role_arn_sha256)) &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage1_role.policy_evidence_sha256)) &&
    can(tolist(local.phase3_stage1_role.effective_write_actions)) &&
    length(local.phase3_stage1_role.effective_write_actions) == 0,
    false
  )

  phase3_stage2_redaction = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage2/redaction-test-results.json"
  )), {})
  phase3_stage2_publisher = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage2/publisher-failure.json"
  )), {})
  phase3_stage2_methods = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage2/public-api-methods.json"
  )), {})
  phase3_stage2_required_redaction_cases = toset([
    "account_id",
    "arn",
    "ip_address",
    "email",
    "access_key",
    "unknown_field",
    "stable_pseudonym",
  ])
  phase3_stage2_evidence_valid = try(
    length(keys(local.phase3_stage2_redaction)) == 8 &&
    local.phase3_stage2_redaction.schema_version == 1 &&
    local.phase3_stage2_redaction.reviewed_by == local.phase3_stage2.reviewed_by &&
    local.phase3_stage2_redaction.reviewed_at == local.phase3_stage2.reviewed_at &&
    can(tolist(local.phase3_stage2_redaction.failed_case_ids)) &&
    length(local.phase3_stage2_redaction.failed_case_ids) == 0 &&
    local.phase3_stage2_redaction.leaked_identifier_count == 0 &&
    local.phase3_stage2_redaction.published_unapproved_fields == 0 &&
    can(tolist(local.phase3_stage2_redaction.passed_case_categories)) &&
    length(distinct(local.phase3_stage2_redaction.passed_case_categories)) == length(local.phase3_stage2_redaction.passed_case_categories) &&
    alltrue([
      for category in local.phase3_stage2_redaction.passed_case_categories :
      can(regex("^\".*\"$", jsonencode(category))) && trimspace(category) != ""
    ]) &&
    length(setintersection(local.phase3_stage2_required_redaction_cases, toset(local.phase3_stage2_redaction.passed_case_categories))) == length(local.phase3_stage2_required_redaction_cases) &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage2_redaction.test_suite_sha256)) &&
    length(keys(local.phase3_stage2_publisher)) == 7 &&
    local.phase3_stage2_publisher.schema_version == 1 &&
    local.phase3_stage2_publisher.reviewed_by == local.phase3_stage2.reviewed_by &&
    local.phase3_stage2_publisher.reviewed_at == local.phase3_stage2.reviewed_at &&
    contains(["redaction", "schema_validation", "publication_write"], local.phase3_stage2_publisher.injected_failure) &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage2_publisher.previous_snapshot_sha256)) &&
    local.phase3_stage2_publisher.published_snapshot_sha256 == local.phase3_stage2_publisher.previous_snapshot_sha256 &&
    local.phase3_stage2_publisher.last_good_preserved == true &&
    length(keys(local.phase3_stage2_methods)) == 4 &&
    local.phase3_stage2_methods.schema_version == 1 &&
    local.phase3_stage2_methods.reviewed_by == local.phase3_stage2.reviewed_by &&
    local.phase3_stage2_methods.reviewed_at == local.phase3_stage2.reviewed_at &&
    length(keys(local.phase3_stage2_methods.method_results)) == 9 &&
    local.phase3_stage2_methods.method_results.GET == "served" &&
    local.phase3_stage2_methods.method_results.HEAD == "served" &&
    alltrue([
      for method in ["OPTIONS", "PATCH", "POST", "PUT", "DELETE", "TRACE", "CONNECT"] :
      local.phase3_stage2_methods.method_results[method] == "rejected"
    ]),
    false
  )

  phase3_stage3_transport = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/transport-security.json"
  )), {})
  phase3_stage3_external_tls_scan = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/external-tls-scan.json"
  )), {})
  phase3_stage3_privacy_accessibility = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/privacy-accessibility.json"
  )), {})
  phase3_stage3_rin_evaluation = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/rin-evaluation.json"
  )), {})
  phase3_stage3_quota_fallbacks = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/quota-fallbacks.json"
  )), {})
  phase3_stage3_failure_banners = try(jsondecode(file(
    "${path.module}/../../../docs/evidence/stage3/failure-banners.json"
  )), {})
  phase3_stage3_required_rin_categories = toset([
    "prompt_injection",
    "hostile_evidence",
    "secret_leakage",
    "citation_grounding",
    "unsupported_question",
    "response_schema",
    "provider_error_fallback",
  ])
  phase3_stage3_runtime_evidence_valid = try(
    length(keys(local.phase3_stage3_transport)) == 8 &&
    local.phase3_stage3_transport.schema_version == 1 &&
    local.phase3_stage3_transport.reviewed_by == local.phase3_stage3.reviewed_by &&
    local.phase3_stage3_transport.reviewed_at == local.phase3_stage3.reviewed_at &&
    contains([301, 302, 307, 308], local.phase3_stage3_transport.http_redirect_status) &&
    local.phase3_stage3_transport.https_status == 200 &&
    length(keys(local.phase3_stage3_transport.headers)) == 5 &&
    local.phase3_stage3_transport.headers.strict_transport_security == true &&
    local.phase3_stage3_transport.headers.content_security_policy == true &&
    local.phase3_stage3_transport.headers.x_content_type_options == true &&
    local.phase3_stage3_transport.headers.referrer_policy == true &&
    local.phase3_stage3_transport.headers.frame_ancestors == true &&
    local.phase3_stage3_transport.external_scan_evidence_path == "stage3/external-tls-scan.json" &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_transport.external_scan_sha256)) &&
    local.phase3_stage3_transport.external_scan_sha256 == filesha256("${path.module}/../../../docs/evidence/stage3/external-tls-scan.json") &&
    length(keys(local.phase3_stage3_external_tls_scan)) == 9 &&
    local.phase3_stage3_external_tls_scan.schema_version == 1 &&
    local.phase3_stage3_external_tls_scan.reviewed_by == local.phase3_stage3.reviewed_by &&
    local.phase3_stage3_external_tls_scan.reviewed_at == local.phase3_stage3.reviewed_at &&
    trimspace(local.phase3_stage3_external_tls_scan.provider) != "" &&
    can(formatdate("YYYY-MM-DD", local.phase3_stage3_external_tls_scan.scanned_at)) &&
    local.phase3_stage3_external_tls_scan.tls_result == "pass" &&
    local.phase3_stage3_external_tls_scan.security_headers_result == "pass" &&
    local.phase3_stage3_external_tls_scan.source_report_evidence_path == "stage3/source-reports/external-tls.json" &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_external_tls_scan.source_report_sha256)) &&
    local.phase3_stage3_external_tls_scan.source_report_sha256 == filesha256("${path.module}/../../../docs/evidence/stage3/source-reports/external-tls.json") &&
    length(keys(local.phase3_stage3_privacy_accessibility)) == 11 &&
    local.phase3_stage3_privacy_accessibility.schema_version == 1 &&
    local.phase3_stage3_privacy_accessibility.reviewed_by == local.phase3_stage3.reviewed_by &&
    local.phase3_stage3_privacy_accessibility.reviewed_at == local.phase3_stage3.reviewed_at &&
    local.phase3_stage3_privacy_accessibility.browser_network_report_evidence_path == "stage3/source-reports/browser-network.json" &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_privacy_accessibility.browser_network_log_sha256)) &&
    local.phase3_stage3_privacy_accessibility.browser_network_log_sha256 == filesha256("${path.module}/../../../docs/evidence/stage3/source-reports/browser-network.json") &&
    can(tolist(local.phase3_stage3_privacy_accessibility.unapproved_third_party_requests)) &&
    length(local.phase3_stage3_privacy_accessibility.unapproved_third_party_requests) == 0 &&
    local.phase3_stage3_privacy_accessibility.lighthouse_report_evidence_path == "stage3/source-reports/lighthouse.json" &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_privacy_accessibility.lighthouse_report_sha256)) &&
    local.phase3_stage3_privacy_accessibility.lighthouse_report_sha256 == filesha256("${path.module}/../../../docs/evidence/stage3/source-reports/lighthouse.json") &&
    local.phase3_stage3_privacy_accessibility.accessibility_report_evidence_path == "stage3/source-reports/accessibility.json" &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_privacy_accessibility.accessibility_report_sha256)) &&
    local.phase3_stage3_privacy_accessibility.accessibility_report_sha256 == filesha256("${path.module}/../../../docs/evidence/stage3/source-reports/accessibility.json") &&
    toset(local.phase3_stage3_privacy_accessibility.pages_checked) == toset(["dashboard", "finding", "rin"]) &&
    length(keys(local.phase3_stage3_rin_evaluation)) == 5 &&
    local.phase3_stage3_rin_evaluation.schema_version == 1 &&
    local.phase3_stage3_rin_evaluation.reviewed_by == local.phase3_stage3.reviewed_by &&
    local.phase3_stage3_rin_evaluation.reviewed_at == local.phase3_stage3.reviewed_at &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_rin_evaluation.test_suite_sha256)) &&
    length(distinct([for case in local.phase3_stage3_rin_evaluation.cases : case.case_id])) == length(local.phase3_stage3_rin_evaluation.cases) &&
    alltrue([
      for case in local.phase3_stage3_rin_evaluation.cases :
      length(keys(case)) == 3 && trimspace(case.case_id) != "" &&
      contains(local.phase3_stage3_required_rin_categories, case.category) && case.passed == true
    ]) &&
    length(setintersection(local.phase3_stage3_required_rin_categories, toset([for case in local.phase3_stage3_rin_evaluation.cases : case.category if case.passed == true]))) == length(local.phase3_stage3_required_rin_categories) &&
    length(keys(local.phase3_stage3_quota_fallbacks)) == 7 &&
    local.phase3_stage3_quota_fallbacks.schema_version == 1 &&
    local.phase3_stage3_quota_fallbacks.reviewed_by == local.phase3_stage3.reviewed_by &&
    local.phase3_stage3_quota_fallbacks.reviewed_at == local.phase3_stage3.reviewed_at &&
    local.phase3_stage3_quota_fallbacks.per_session_limit == 10 &&
    local.phase3_stage3_quota_fallbacks.daily_invocation_limit > 0 &&
    var.provider_monthly_budget_usd != null &&
    local.phase3_stage3_quota_fallbacks.daily_invocation_limit == local.rin_daily_cap &&
    local.phase3_stage3_quota_fallbacks.monthly_budget_usd == var.provider_monthly_budget_usd &&
    length(keys(local.phase3_stage3_quota_fallbacks.cases)) == 3 &&
    alltrue([for control in ["session", "daily", "monthly_budget"] : local.phase3_stage3_quota_fallbacks.cases[control].limit_reached == true && local.phase3_stage3_quota_fallbacks.cases[control].response_mode == "fixture"]) &&
    length(keys(local.phase3_stage3_failure_banners)) == 5 &&
    local.phase3_stage3_failure_banners.schema_version == 1 &&
    local.phase3_stage3_failure_banners.reviewed_by == local.phase3_stage3.reviewed_by &&
    local.phase3_stage3_failure_banners.reviewed_at == local.phase3_stage3.reviewed_at &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_failure_banners.test_suite_sha256)) &&
    toset(keys(local.phase3_stage3_failure_banners.rendered_states)) == toset([
      "partial_scan", "failed_scan", "stale_data", "publication_blocked",
      "api_unavailable", "rin_unavailable", "rin_over_budget", "kill_switch_static_mode"
    ]) &&
    alltrue([for state, rendered in local.phase3_stage3_failure_banners.rendered_states : rendered == true]),
    false
  )

  phase3_stage3_reviews_valid = try(
    length(keys(local.phase3_stage3_guardrail_review)) == 10 &&
    local.phase3_stage3_guardrail_review.schema_version == 1 &&
    floor(local.phase3_stage3_guardrail_review.schema_version) == local.phase3_stage3_guardrail_review.schema_version &&
    local.phase3_stage3_guardrail_review.reviewed_by == local.phase3_stage3.reviewed_by &&
    local.phase3_stage3_guardrail_review.reviewed_at == local.phase3_stage3.reviewed_at &&
    can(regex(
      "^arn:(aws|aws-us-gov|aws-cn):bedrock:[a-z0-9-]+:[0-9]{12}:guardrail/[a-z0-9]+$",
      local.phase3_stage3_guardrail_review.guardrail_arn
    )) &&
    can(regex("^[1-9][0-9]{0,7}$", local.phase3_stage3_guardrail_review.published_version)) &&
    local.phase3_stage3_guardrail_review.configuration_evidence_path == "stage3/guardrail-configuration.json" &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_guardrail_review.configuration_sha256)) &&
    local.phase3_stage3_guardrail_review.configuration_sha256 == filesha256(
      "${path.module}/../../../docs/evidence/stage3/guardrail-configuration.json"
    ) &&
    length(keys(local.phase3_stage3_guardrail_configuration)) == 5 &&
    local.phase3_stage3_guardrail_configuration.schema_version == 1 &&
    floor(local.phase3_stage3_guardrail_configuration.schema_version) == local.phase3_stage3_guardrail_configuration.schema_version &&
    local.phase3_stage3_guardrail_configuration.guardrail_arn == local.phase3_stage3_guardrail_review.guardrail_arn &&
    local.phase3_stage3_guardrail_configuration.published_version == local.phase3_stage3_guardrail_review.published_version &&
    local.phase3_stage3_guardrail_configuration.input_controls == local.phase3_stage3_guardrail_review.input_controls &&
    local.phase3_stage3_guardrail_configuration.output_controls == local.phase3_stage3_guardrail_review.output_controls &&
    length(keys(local.phase3_stage3_guardrail_review.input_controls)) == 3 &&
    length(keys(local.phase3_stage3_guardrail_review.output_controls)) == 3 &&
    alltrue([
      for controls in [
        local.phase3_stage3_guardrail_review.input_controls,
        local.phase3_stage3_guardrail_review.output_controls,
      ] :
      controls.prompt_attack_filter == true &&
      controls.sensitive_data_filter == true &&
      length(controls.off_scope_topics) > 0 &&
      length(controls.off_scope_topics) <= 100 &&
      alltrue([for topic in controls.off_scope_topics : trimspace(topic) != ""])
    ]) &&
    length(keys(local.phase3_stage3_guardrail_review.evaluation)) == 4 &&
    local.phase3_stage3_guardrail_review.evaluation.evidence_path == "stage3/guardrail-evaluation.json" &&
    local.phase3_stage3_guardrail_review.evaluation.passed == true &&
    local.phase3_stage3_guardrail_review.evaluation.case_count > 0 &&
    floor(local.phase3_stage3_guardrail_review.evaluation.case_count) == local.phase3_stage3_guardrail_review.evaluation.case_count &&
    can(regex("^[a-f0-9]{64}$", local.phase3_stage3_guardrail_review.evaluation.sha256)) &&
    local.phase3_stage3_guardrail_review.evaluation.sha256 == filesha256(
      "${path.module}/../../../docs/evidence/stage3/guardrail-evaluation.json"
    ) &&
    length(keys(local.phase3_stage3_guardrail_evaluation)) == 6 &&
    local.phase3_stage3_guardrail_evaluation.schema_version == 1 &&
    floor(local.phase3_stage3_guardrail_evaluation.schema_version) == local.phase3_stage3_guardrail_evaluation.schema_version &&
    local.phase3_stage3_guardrail_evaluation.guardrail_arn == local.phase3_stage3_guardrail_review.guardrail_arn &&
    local.phase3_stage3_guardrail_evaluation.published_version == local.phase3_stage3_guardrail_review.published_version &&
    local.phase3_stage3_guardrail_evaluation.passed == true &&
    local.phase3_stage3_guardrail_evaluation.passed == local.phase3_stage3_guardrail_review.evaluation.passed &&
    local.phase3_stage3_guardrail_evaluation.case_count == local.phase3_stage3_guardrail_review.evaluation.case_count &&
    floor(local.phase3_stage3_guardrail_evaluation.case_count) == local.phase3_stage3_guardrail_evaluation.case_count &&
    length(local.phase3_stage3_guardrail_evaluation.cases) == local.phase3_stage3_guardrail_evaluation.case_count &&
    length(distinct([for case in local.phase3_stage3_guardrail_evaluation.cases : case.case_id])) == local.phase3_stage3_guardrail_evaluation.case_count &&
    alltrue([
      for case in local.phase3_stage3_guardrail_evaluation.cases :
      length(keys(case)) == 5 &&
      trimspace(case.case_id) != "" &&
      case.passed == true &&
      ((contains([
        "input_prompt_attack",
        "input_sensitive_data",
        "input_off_scope",
        "output_prompt_attack",
        "output_sensitive_data",
        "output_off_scope",
        ], case.category) && case.expected_action == "BLOCK" && case.observed_action == "BLOCK") ||
      (case.category == "safe_in_scope" && case.expected_action == "ALLOW" && case.observed_action == "ALLOW"))
    ]) &&
    alltrue([
      for category in local.phase3_stage3_required_evaluation_categories :
      contains([for case in local.phase3_stage3_guardrail_evaluation.cases : case.category], category)
    ]) &&
    length(keys(local.phase3_stage3_logging_review)) == 8 &&
    local.phase3_stage3_logging_review.schema_version == 1 &&
    floor(local.phase3_stage3_logging_review.schema_version) == local.phase3_stage3_logging_review.schema_version &&
    local.phase3_stage3_logging_review.guardrail_arn == local.phase3_stage3_guardrail_review.guardrail_arn &&
    local.phase3_stage3_logging_review.published_version == local.phase3_stage3_guardrail_review.published_version &&
    local.phase3_stage3_logging_review.reviewed_by == local.phase3_stage3.reviewed_by &&
    local.phase3_stage3_logging_review.reviewed_at == local.phase3_stage3.reviewed_at &&
    local.phase3_stage3_logging_review.maximum_prompt_retention_days >= 0 &&
    local.phase3_stage3_logging_review.maximum_prompt_retention_days <= 30 &&
    floor(local.phase3_stage3_logging_review.maximum_prompt_retention_days) == local.phase3_stage3_logging_review.maximum_prompt_retention_days &&
    length(keys(local.phase3_stage3_logging_review.bedrock_model_invocation_logging)) == 5 &&
    local.phase3_stage3_logging_review.bedrock_model_invocation_logging.evidence_path == "stage3/bedrock-logging-settings.json" &&
    local.phase3_stage3_logging_review.bedrock_model_invocation_logging.settings_sha256 == filesha256(
      "${path.module}/../../../docs/evidence/stage3/bedrock-logging-settings.json"
    ) &&
    length(keys(local.phase3_stage3_logging_review.external_provider_logging)) == 6 &&
    local.phase3_stage3_logging_review.external_provider_logging.evidence_path == "stage3/external-provider-logging-settings.json" &&
    local.phase3_stage3_logging_review.external_provider_logging.settings_sha256 == filesha256(
      "${path.module}/../../../docs/evidence/stage3/external-provider-logging-settings.json"
    ) &&
    length(keys(local.phase3_stage3_bedrock_logging)) == 4 &&
    local.phase3_stage3_bedrock_logging.schema_version == 1 &&
    floor(local.phase3_stage3_bedrock_logging.schema_version) == local.phase3_stage3_bedrock_logging.schema_version &&
    local.phase3_stage3_bedrock_logging.enabled == local.phase3_stage3_logging_review.bedrock_model_invocation_logging.enabled &&
    local.phase3_stage3_bedrock_logging.includes_prompt_content == local.phase3_stage3_logging_review.bedrock_model_invocation_logging.includes_prompt_content &&
    local.phase3_stage3_bedrock_logging.retention_days == local.phase3_stage3_logging_review.bedrock_model_invocation_logging.retention_days &&
    length(keys(local.phase3_stage3_external_logging)) == 5 &&
    local.phase3_stage3_external_logging.schema_version == 1 &&
    floor(local.phase3_stage3_external_logging.schema_version) == local.phase3_stage3_external_logging.schema_version &&
    local.phase3_stage3_external_logging.provider == local.phase3_stage3_logging_review.external_provider_logging.provider &&
    local.phase3_stage3_external_logging.enabled == local.phase3_stage3_logging_review.external_provider_logging.enabled &&
    local.phase3_stage3_external_logging.includes_prompt_content == local.phase3_stage3_logging_review.external_provider_logging.includes_prompt_content &&
    local.phase3_stage3_external_logging.retention_days == local.phase3_stage3_logging_review.external_provider_logging.retention_days &&
    alltrue([
      for logging in [
        local.phase3_stage3_logging_review.bedrock_model_invocation_logging,
        local.phase3_stage3_logging_review.external_provider_logging,
      ] :
      can(regex("^[a-f0-9]{64}$", logging.settings_sha256)) &&
      (logging.enabled == true || logging.enabled == false) &&
      (logging.includes_prompt_content == true || logging.includes_prompt_content == false) &&
      try(
        logging.retention_days >= 0 && floor(logging.retention_days) == logging.retention_days,
        logging.retention_days == null
      ) &&
      (!logging.includes_prompt_content || (
        logging.enabled == true &&
        try(logging.retention_days <= local.phase3_stage3_logging_review.maximum_prompt_retention_days, false)
      ))
    ]) &&
    trimspace(local.phase3_stage3_logging_review.external_provider_logging.provider) != "" &&
    (!var.rin_enabled || (
      local.phase3_stage3_guardrail_review.guardrail_arn == var.rin_guardrail_arn &&
      local.phase3_stage3_guardrail_review.published_version == var.rin_guardrail_version
    )),
    false
  )

  phase3_stage1_passed = local.phase3_stage_schema_valid && try(
    local.phase3_stage1.status == "passed" &&
    trimspace(local.phase3_stage1.reviewed_by) != "" &&
    formatdate("YYYY", local.phase3_stage1.reviewed_at) != "" &&
    length(keys(local.phase3_stage1.criteria)) == 3 &&
    alltrue([
      local.phase3_stage1.criteria.two_consecutive_scheduled_scans == true,
      local.phase3_stage1.criteria.reviewed_new_and_resolved_drift == true,
      local.phase3_stage1.criteria.read_only_target_role_evidence == true,
    ]) &&
    local.phase3_stage1_evidence_valid &&
    length(local.phase3_stage1.evidence) > 0 &&
    alltrue([
      for required_path in [
        "stage1/scheduled-scan-results.json",
        "stage1/schedule-execution-log.json",
        "stage1/drift-review.json",
        "stage1/read-only-role-review.json",
      ] : contains(local.phase3_stage1.evidence, required_path)
    ]) &&
    length(keys(local.phase3_stage1.evidence_sha256)) == length(local.phase3_stage1.evidence) &&
    alltrue([
      for evidence_path in local.phase3_stage1.evidence :
      startswith(evidence_path, "stage1/") &&
      !contains(split("/", evidence_path), "..") &&
      fileexists("${path.module}/../../../docs/evidence/${evidence_path}") &&
      can(regex("^[a-f0-9]{64}$", local.phase3_stage1.evidence_sha256[evidence_path])) &&
      filesha256("${path.module}/../../../docs/evidence/${evidence_path}") == local.phase3_stage1.evidence_sha256[evidence_path]
    ]),
    false
  )

  phase3_stage2_passed = local.phase3_stage_schema_valid && try(
    local.phase3_stage2.status == "passed" &&
    trimspace(local.phase3_stage2.reviewed_by) != "" &&
    formatdate("YYYY", local.phase3_stage2.reviewed_at) != "" &&
    length(keys(local.phase3_stage2.criteria)) == 3 &&
    alltrue([
      local.phase3_stage2.criteria.redaction_and_secret_tests == true,
      local.phase3_stage2.criteria.publisher_failure_atomicity == true,
      local.phase3_stage2.criteria.public_api_method_tests == true,
    ]) &&
    local.phase3_stage2_evidence_valid &&
    length(local.phase3_stage2.evidence) > 0 &&
    alltrue([
      for required_path in [
        "stage2/redaction-test-results.json",
        "stage2/publisher-failure.json",
        "stage2/public-api-methods.json",
      ] : contains(local.phase3_stage2.evidence, required_path)
    ]) &&
    length(keys(local.phase3_stage2.evidence_sha256)) == length(local.phase3_stage2.evidence) &&
    alltrue([
      for evidence_path in local.phase3_stage2.evidence :
      startswith(evidence_path, "stage2/") &&
      !contains(split("/", evidence_path), "..") &&
      fileexists("${path.module}/../../../docs/evidence/${evidence_path}") &&
      can(regex("^[a-f0-9]{64}$", local.phase3_stage2.evidence_sha256[evidence_path])) &&
      filesha256("${path.module}/../../../docs/evidence/${evidence_path}") == local.phase3_stage2.evidence_sha256[evidence_path]
    ]),
    false
  )

  phase3_stage3_passed = local.phase3_stage_schema_valid && try(
    local.phase3_stage3.status == "passed" &&
    trimspace(local.phase3_stage3.reviewed_by) != "" &&
    formatdate("YYYY", local.phase3_stage3.reviewed_at) != "" &&
    length(keys(local.phase3_stage3.criteria)) == 6 &&
    alltrue([
      local.phase3_stage3.criteria.https_and_security_headers == true,
      local.phase3_stage3.criteria.rin_evaluation == true,
      local.phase3_stage3.criteria.quota_fallbacks == true,
      local.phase3_stage3.criteria.failure_banners == true,
      local.phase3_stage3.criteria.published_guardrail_policy_review == true,
      local.phase3_stage3.criteria.bedrock_invocation_logging_review == true,
    ]) &&
    local.phase3_stage3_runtime_evidence_valid &&
    length(local.phase3_stage3.evidence) > 0 &&
    contains(local.phase3_stage3.evidence, "stage3/guardrail-policy-review.json") &&
    contains(local.phase3_stage3.evidence, "stage3/bedrock-logging-review.json") &&
    contains(local.phase3_stage3.evidence, "stage3/transport-security.json") &&
    contains(local.phase3_stage3.evidence, "stage3/external-tls-scan.json") &&
    contains(local.phase3_stage3.evidence, "stage3/source-reports/external-tls.json") &&
    contains(local.phase3_stage3.evidence, "stage3/privacy-accessibility.json") &&
    contains(local.phase3_stage3.evidence, "stage3/source-reports/browser-network.json") &&
    contains(local.phase3_stage3.evidence, "stage3/source-reports/lighthouse.json") &&
    contains(local.phase3_stage3.evidence, "stage3/source-reports/accessibility.json") &&
    contains(local.phase3_stage3.evidence, "stage3/rin-evaluation.json") &&
    contains(local.phase3_stage3.evidence, "stage3/quota-fallbacks.json") &&
    contains(local.phase3_stage3.evidence, "stage3/failure-banners.json") &&
    contains(local.phase3_stage3.evidence, "stage3/guardrail-configuration.json") &&
    contains(local.phase3_stage3.evidence, "stage3/guardrail-evaluation.json") &&
    contains(local.phase3_stage3.evidence, "stage3/bedrock-logging-settings.json") &&
    contains(local.phase3_stage3.evidence, "stage3/external-provider-logging-settings.json") &&
    length(keys(local.phase3_stage3.evidence_sha256)) == length(local.phase3_stage3.evidence) &&
    local.phase3_stage3_reviews_valid &&
    alltrue([
      for evidence_path in local.phase3_stage3.evidence :
      startswith(evidence_path, "stage3/") &&
      !contains(split("/", evidence_path), "..") &&
      fileexists("${path.module}/../../../docs/evidence/${evidence_path}") &&
      can(regex("^[a-f0-9]{64}$", local.phase3_stage3.evidence_sha256[evidence_path])) &&
      filesha256("${path.module}/../../../docs/evidence/${evidence_path}") == local.phase3_stage3.evidence_sha256[evidence_path]
    ]),
    false
  )
}

resource "terraform_data" "phase3_stage_acceptance_gate" {
  input = {
    stage1_passed = local.phase3_stage1_passed
    stage2_passed = local.phase3_stage2_passed
    stage3_passed = local.phase3_stage3_passed
  }

  lifecycle {
    precondition {
      condition     = !var.enable_stage2 || local.phase3_stage1_passed
      error_message = "Stage 2 requires reviewed, checked-in Stage 1 acceptance evidence."
    }
    precondition {
      condition     = !var.enable_stage3 || (local.phase3_stage1_passed && local.phase3_stage2_passed)
      error_message = "Stage 3 requires reviewed, checked-in Stage 1 and Stage 2 acceptance evidence."
    }
    precondition {
      condition     = !var.enable_stage4 || (local.phase3_stage1_passed && local.phase3_stage2_passed && local.phase3_stage3_passed)
      error_message = "Stage 4 requires reviewed, checked-in Stage 1, Stage 2, and Stage 3 acceptance evidence."
    }
    precondition {
      condition = !var.rin_enabled || try(
        local.phase3_stage3_guardrail_review.guardrail_arn == var.rin_guardrail_arn &&
        local.phase3_stage3_guardrail_review.published_version == var.rin_guardrail_version,
        false
      )
      error_message = "Live Rin must use the exact Guardrail ARN and published version covered by the reviewed Stage 3 evidence."
    }
  }
}
