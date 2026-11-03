# Vorrin

Read-only AWS account security for IAM, S3, and CloudTrail. Vorrin inspects
configuration, records evidence, and produces findings you can review.

[Open the console demo](https://tdinh-dev-sec-scientist.github.io/account-access-auditor/console/) ·
[Open the scan replay](https://tdinh-dev-sec-scientist.github.io/account-access-auditor/) ·
[Review Phase 2 status](docs/implementation-status.md)

**Phase 2 is release-complete under the approved read-only Stage 6 amendment.**
AWS assessment remains read-only. AWS sandbox apply is not implemented or claimed;
the [Stage 6 amendment](docs/phase2-stage6-amendment.md) records the
approved acceptance. See the [release status](docs/implementation-status.md)
for stage evidence and limitations.

## Quick start

After dependencies are installed, the local Moto lab needs no AWS account,
credentials, or network access.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m lab.demo --output-dir reports
```

The scan writes JSON, CSV, terminal, and HTML reports to `reports/`.

To build and preview the saved-data site locally:

```bash
python -m lab.run_benchmark
python scripts/build_site.py
python -m http.server --directory site 8000
```

Open `http://localhost:8000` for the scan replay or
`http://localhost:8000/console/` for the security console. The replay is
generated from saved Moto artifacts; a static page cannot make AWS API calls.

## What Phase 2 includes

| Area | Included |
| --- | --- |
| AWS audit | Read-only IAM, S3, and CloudTrail checks with evidence, severity, and CIS mapping |
| Infrastructure as code | Checkov and Conftest scans with normalized findings and policy gates |
| CI and Kubernetes | GitHub workflow feedback, Kubernetes controls, and Gatekeeper admission policies |
| Drift | Scheduled local scans and persistent local history |
| Supply chain | SBOMs, vulnerability reports, policy gates, and signed local release artifacts |
| Exceptions and remediation | Expiring exceptions, reviewed pull requests, and local-copy rescans |
| AI analyst | Optional cited explanations and local patch proposals; no AWS access or gate authority |
| Security console | Static, offline demo of checked-in findings with saved dark and light themes |

The stage-by-stage evidence, acceptance results, and known gaps are in
[implementation status](docs/implementation-status.md). Detailed controls live
in the linked documentation below.

## Measured results

The figures are generated from repository artifacts. Run
`python scripts/collect_metrics.py` to refresh the evidence and README table.
The exact test and coverage values are in `results/metrics.json`.

<!-- BEGIN GENERATED METRICS -->

| Metric                                 |        Value | Evidence |
| -------------------------------------- | -----------: | -------- |
| Security rules                         |           14 | `results/metrics_sources.json` |
| Lab findings (misconfigured profile)   |           25 | `results/aws_audit_results.json` |
| Detection rate                         | 100% (25 TP / 0 FN / 0 FP) | `results/expected_vs_actual.json` |
| Offline fixture cases                  |           98 | `results/fixture_manifest.json` |
| Fixture cases by category              | clean=17, edge=39, malformed=8, multi=9, severity=6, vulnerable=19 | `results/fixture_manifest.json` |
| Fixture cases by service               | cloudtrail=15, iam=48, s3=35 | `results/fixture_manifest.json` |
| Tests passing                          | PASS (exact count in results/metrics.json) | `results/metrics.json` |
| Detection-code coverage                | Exact percentage in results/metrics.json | `results/metrics.json` |
| Overall package coverage               | PASS (86% CI floor) | `results/metrics.json` |
| CIS-mapped rules                       | 11/14 (v3.0.0) | `results/metrics_sources.json` |
| Self-audit of the auditor's own policy |         PASS | `results/metrics_sources.json` |
| API calls per full scan                |          101 | `results/aws_audit_results.json` |

<!-- END GENERATED METRICS -->

The 100% figure describes this labeled Moto fixture corpus. It is not a
real-world precision or recall estimate. The test account and its limits are
described in [the lab guide](docs/test-environment.md).

## Security boundary

- **AWS access:** collectors use read-only operations. The console does not
  connect to AWS; Stage 6 uses the approved read-only local-copy workflow.
- **Credentials:** the static demo contains no AWS credentials and makes no
  network requests. CI does not receive AWS credentials.
- **Reports:** the standalone HTML report contains no JavaScript, loads no
  external resources, and escapes account-controlled values.
- **Rin:** the floating evidence guide answers from the checked-in report. No
  AI model is connected.
- **Hosting:** the demo is static GitHub Pages on the default `github.io`
  domain, where HTTPS is enforced. There is no application server or inbound
  port to configure with a project-level firewall.

See the [threat model](docs/threat-model.md), [least-privilege policy
notes](docs/least-privilege.md), and [operations runbook](docs/operations-runbook.md).

## Project map

| Path | Purpose |
| --- | --- |
| `auditor/` | AWS collection, rules, policy validation, and report generation |
| `iac/`, `k8s/`, `supply_chain/` | Infrastructure, Kubernetes, and release scanning |
| `schemas/`, `contract/` | Versioned findings and scan artifacts |
| `scripts/console/` | Static Vorrin console and local assistant |
| `lab/`, `tests/` | Moto environment, fixtures, and automated checks |
| `docs/` | Stage status, controls, architecture, operations, and limitations |
| `results/` | Generated evidence used by reports and demos |

## Tests and tools

Run the standard suite with:

```bash
pytest -q
```

The full Phase 2 checks also use the pinned Checkov and Conftest tools. Follow
[the IaC setup guide](docs/iac-scanning.md) to install them. CI installs these
versions before running tests and collecting metrics. Optional live checks,
including Gatekeeper admission, are documented in the [operations runbook](docs/operations-runbook.md).

## Documentation

- [Phase 2 acceptance and limitations](docs/implementation-status.md)
- [Threat model](docs/threat-model.md)
- [Architecture decisions](docs/architecture/README.md)
- [AWS permissions and read-only behavior](docs/least-privilege.md)
- [IaC and policy scanning](docs/iac-scanning.md)
- [CIS mapping](docs/cis-mapping.md)
- [Kubernetes, fleet, and supply-chain scanning](docs/fleet-scanning.md), [supply-chain release](docs/supply-chain.md)
- [Exceptions and remediation](docs/remediation.md), [AI analyst](docs/ai-analyst.md)
- [Test lab](docs/test-environment.md), [operations runbook](docs/operations-runbook.md)

## Known limits

Vorrin reports observed configuration; it does not calculate effective
permissions or prove exploitability. Root-account checks, password-policy
checks, object-level S3 controls, and multi-region collection are outside the
current AWS audit scope. Managed AWS scheduling and storage are not included.
See [Phase 2 status](docs/implementation-status.md) for the complete list.

## License

MIT. See [LICENSE](LICENSE).
