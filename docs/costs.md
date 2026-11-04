# Phase 3 cost record

This file is the cost evidence record required by the Phase 3 plan. Owner values
remain unset until a current estimate and deployment boundary are supplied.

## Before deployment

| Record | Value |
| --- | --- |
| AWS Pricing Calculator monthly estimate | **Not recorded** |
| Calculator export or evidence reference | **Not recorded** |
| Owner-approved monthly AWS cap | **Not recorded** |
| AWS region and traffic assumptions | **Not recorded** |
| External provider and approved model | **Not selected** |
| Provider input/output rates and evidence date | **Not recorded** |
| Separate provider monthly budget | **Not recorded** |
| Monthly budget notification recipient | **Not configured** |

The Phase 3 control-plane Terraform keeps the public stage disabled until the
AWS estimate reference is present and the owner-set monthly cap covers the
estimate. Live Rin also stays disabled until a separate provider budget, model,
current input/output token rates, and a published Bedrock Guardrail ARN/version
produce a positive daily cap.

## Cost controls in code

- AWS Budgets sends actual-spend alerts at 50%, 80%, and 100% of the configured
  monthly AWS cap. The 100% notification invokes the kill switch, which disables
  Rin and selects static fixture mode.
- AWS Budgets notifications can be delayed and **are not hard spend limits**.
  They cannot prevent charges already incurred or still accruing.
- Rin enforces a ten-question browser-session limit and an atomic global daily
  provider-call cap. Its cap is derived from the owner-entered provider monthly
  budget and current per-token rates, reserving 20% of that budget and capping
  at 1,000 calls per day. A blocked request emits only an aggregate metric; it
  does not log a session token or question text.
- Each live Rin request also makes two Bedrock Guardrail evaluations: one for
  the bounded redacted input before the external model call and one for the
  validated response before it reaches the visitor. Include both evaluations
  in the AWS estimate and monthly cap; they incur Guardrail evaluation charges.
- WAF limits API traffic to 100 requests per IP per five minutes. Provider input
  bytes and output tokens are bounded before a call. The live API, Rin, and
  scanners cannot create, update, or delete target-account resources.
- Scheduled scans are disabled by default and are limited to the dedicated
  demo account. The demo resources are empty S3 buckets and IAM/S3 settings;
  no compute instance, NAT gateway, access key, or data-bearing public bucket
  is part of the demo.

The controls bound expected usage; the owner must still verify provider billing
and alert features, AWS service pricing, request volume, and account-level fees
before enabling traffic.

## Actual costs after launch

| Month (UTC) | AWS actual spend | External provider actual spend | Evidence |
| --- | --- | --- | --- |
| Not deployed | **Not recorded** | **Not recorded** | No Phase 3 resources have been created. |

After launch, update this table monthly using AWS Cost Explorer and the chosen
provider's billing records. Record the period, currency, account scope, and
export or report reference. Do not substitute Moto request counts or a
calculator estimate for actual spend.
