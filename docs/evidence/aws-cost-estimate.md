# Phase 3 AWS monthly cost estimate

Reviewed by Truong Dinh on 2026-11-07. This is the estimate behind the
`PHASE3_AWS_ESTIMATE_MONTHLY_USD` and `PHASE3_AWS_ESTIMATE_REFERENCE`
variables that Stage 2 requires.

**Estimate: $2.43 per month, recorded as $3. Owner cap
(`PHASE3_MONTHLY_BUDGET_USD`): $10.**

## Method

Prices are the us-east-1 on-demand rates from the AWS Price List API
(`https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<offer>/current/us-east-1/index.json`),
read on 2026-11-07 (CloudFront from its global offer file). The free tier is **not** subtracted, so the estimate is an
upper bound for this usage. Usage is sized for the six-hour schedule
(120 scheduled scans a month) plus about 10 manual scans and light console
traffic from invited users.

| Service | Usage per month | Unit price (offer publication date) | Cost |
| --- | --- | --- | ---: |
| AWS Fargate (0.5 vCPU, 1 GB) | 130 tasks × 2 min = 4.33 h | $0.04048 per vCPU-hour, $0.004445 per GB-hour (AmazonECS, 2026-10-19) | $0.11 |
| Public IPv4 for Fargate tasks | 4.33 h | $0.005 per hour (AmazonVPC, 2026-11-05) | $0.02 |
| AWS Secrets Manager | 2 secrets (pseudonym key, Rin provider key), 1,000 calls | $0.40 per secret, $0.05 per 10,000 calls (2026-09-11) | $0.81 |
| Amazon ECR | 1 GB of scan images | $0.10 per GB-month (2026-09-11) | $0.10 |
| AWS Lambda | 5,000 invocations × 512 MB × 2 s | $0.20 per million requests, $0.0000166667 per GB-second (2026-10-30) | $0.09 |
| Amazon API Gateway (REST) | 10,000 requests | $3.50 per million (2026-10-13) | $0.04 |
| Amazon DynamoDB on-demand | 50,000 writes, 50,000 reads, 1 GB stored, PITR on 1 GB | $0.625 / $0.125 per million, $0.25 per GB, $0.20 per GB PITR (2026-11-05) | $0.49 |
| Amazon S3 Standard | 2 GB, 10,000 PUT/LIST, 20,000 GET | $0.023 per GB, $0.005 per 1,000, $0.004 per 10,000 (2026-11-04) | $0.11 |
| Amazon CloudWatch Logs | 1 GB ingested and stored | $0.50 per GB ingested, $0.03 per GB-month (2026-11-04) | $0.53 |
| AWS Step Functions (standard) | 130 executions × 10 transitions | $0.000025 per transition (2026-11-04) | $0.03 |
| Amazon CloudFront | 1 GB out, 10,000 HTTPS requests | $0.085 per GB, $0.01 per 10,000 HTTPS requests (2026-10-19) | $0.10 |
| Amazon Cognito (Essentials) | under 10 monthly active users | under the 10,000 MAU free tier (2026-10-20) | $0.00 |
| **Total** | | | **$2.43** |

The demo account's CloudTrail trail is its first management-event trail,
which carries no trail charge; its S3 log storage is within the S3 line.
AWS WAF is off in `invite_only` mode, and Rin's external model provider is
budgeted separately (`PHASE3_PROVIDER_MONTHLY_BUDGET_USD`).

Stage 4 records actual spend from Cost Explorer against this estimate.
