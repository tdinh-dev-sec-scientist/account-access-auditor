# User-approved Stage 6 read-only acceptance amendment (2026-11-02)

This amendment supplements and controls the Stage 6 and Section 13 acceptance
language in [`AWS_Cloud_Security_Guardrails_Phase_2_Final_Plan.docx`](plans/AWS_Cloud_Security_Guardrails_Phase_2_Final_Plan.docx)
for this repository. The user approved keeping AWS read-only and revising the
Stage 6 release acceptance accordingly.

## Security boundary

The auditor remains AWS read-only. This amendment does not implement or claim AWS sandbox apply.
It adds no AWS write API, IAM write permission, remediator
role, or scanner-side cloud apply path. A local temporary-copy simulation is
not AWS remediation.

## Plan language superseded

This amendment supersedes the plan's direct AWS apply acceptance in Sections
4.1, 5.2, 5.3, and 9.3; the Stage 6 implementation and acceptance-impact text;
and the Section 13 criterion “Remediation previews can be rescanned; direct
apply is sandbox-only.” The original AWS sandbox apply remains unimplemented
and must not be described as available.

## Amended Stage 6 acceptance

Stage 6 satisfies the revised repository acceptance only when automated
checks demonstrate all of the following:

- Expired exceptions stop suppressing findings and remain visible and
  auditable.
- Invalid, unapproved, stale, or unsafe remediation is blocked.
- An approved patch is applied only to a private temporary local copy; the
  source tree and AWS remain unchanged.
- A complete IaC rescan is mandatory, and a failed, incomplete, or still
  vulnerable result blocks the proposal.
- Production changes continue through a reviewed pull request and the normal
  deployment approval process.
- Permission inventories and tests continue to reject AWS write operations
  and show no AWS apply role or direct-apply path.

## Release effect

This amendment changes only the Stage 6 direct-AWS-apply criterion. All
remaining Section 13 criteria remain required and must have current evidence
before Phase 2 is reported release-complete. The implementation-status page
records that evidence and any untested live integrations or scope limitations.
