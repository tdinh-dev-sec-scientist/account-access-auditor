# Vorrin

**Read-only AWS security auditing with evidence reviewers can inspect.** Vorrin
checks IAM, S3, and CloudTrail configuration, then produces findings with
severity, rationale, and remediation guidance. The repository also includes
IaC, Kubernetes, CI, and supply-chain security checks.

[Open the interactive console](https://tdinh-dev-sec-scientist.github.io/Vorrin/console/) ·
[Watch the scan replay](https://tdinh-dev-sec-scientist.github.io/Vorrin/) ·
[Read a sample report](https://tdinh-dev-sec-scientist.github.io/Vorrin/report.html) ·
[Inspect the JSON evidence](https://tdinh-dev-sec-scientist.github.io/Vorrin/aws_audit_results.json)

> **Demo boundary:** the public site uses saved results from an emulated Moto
> account. It does not connect to AWS, accept credentials, or run scans against
> visitors' accounts. Live AWS deployment and acceptance are not available in
> this demo.

## Try the console

No account, sign-in, or setup is required. Use this short path to explore it or
record a walkthrough:

1. Open the [interactive console](https://tdinh-dev-sec-scientist.github.io/Vorrin/console/).
2. Switch between **Misconfigured fixture** and **No CloudTrail fixture** to
   compare two saved audit scenarios.
3. Choose **Findings**, filter by severity, then open a finding to see its
   evidence, affected resource, and remediation guidance.
4. Choose **Security Scans** to compare scan execution with the security gate.
   A completed scan can still contain findings; `NOT CONFIGURED` is not a pass.
5. Open **Rin** in the lower-right corner and ask about the selected fixture.
   Answers are local and evidence-based; no model is connected.
6. Toggle light/dark mode or collapse the sidebar for the recording layout you
   prefer.

The report and JSON links in the console let you check the displayed results
against their source artifacts.

## What is included

- **AWS audit:** read-only IAM, S3, and CloudTrail collection with 14
  deterministic checks and structured reports.
- **Infrastructure and policy:** Terraform, IAM policy, Kubernetes, and
  rendered Helm scanning with normalized findings and policy gates.
- **Delivery guardrails:** credential-free CI feedback, supply-chain
  inventory, vulnerability checks, and signed local release artifacts.
- **Review workflows:** drift history, expiring exceptions, and remediation
  proposals that are rescanned in a temporary local copy.
- **Evidence console:** a static, read-only interface for exploring saved
  findings, report details, and fixture-backed answers.

Rin is a local fixture assistant in the public demo. Optional AI integrations
are documented in the repository but are not connected to the published site.

## Run it locally

Requirements: Python 3.11 or 3.12. The fixture benchmark needs no AWS account,
credentials, or live AWS access.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m lab.run_benchmark
python scripts/build_site.py
python -m http.server --directory site 8000
```

Open `http://localhost:8000/console/` for the interactive console or
`http://localhost:8000/` for the scan replay. The benchmark writes its reports
under `results/`; the site is built from those generated files.

## Benchmark results

These numbers come from the checked-in, labeled fixture corpus. They describe
that corpus only; they are not a real-world accuracy estimate. Refresh the
generated evidence with `python scripts/collect_metrics.py`.

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

## Security and scope

- The AWS collector uses read-only operations. It does not create, update, or
  delete AWS resources.
- The public console is static and contains no AWS credentials. Fixture mode
  makes no requests to AWS or an AI provider.
- Findings describe observed configuration; they do not calculate effective
  permissions or prove exploitability.
- The public demo is hosted on GitHub Pages with HTTPS. It has no application
  server, inbound listener, or project-managed firewall.

## Development checks

```bash
python -m pytest -q
node --test tests/*.test.cjs
ruff check auditor lab tests scripts
ruff format --check auditor lab tests scripts
```

CI also validates the Phase 3 Terraform roots and runs the pinned IaC security
scanners. See [IaC scanning](docs/iac-scanning.md) for local scanner setup.

## Repository map

| Path | Contents |
| --- | --- |
| `auditor/` | AWS collectors, security rules, policy checks, and reporters |
| `iac/`, `k8s/`, `supply_chain/` | Infrastructure, cluster, and release scanning |
| `scripts/console/` | Static console, navigation, and local evidence assistant |
| `lab/`, `tests/` | Moto benchmark, test cases, and regression tests |
| `schemas/`, `contract/` | Versioned findings and scan evidence contracts |
| `docs/` | Security model, architecture, operations, and tool guides |
| `results/` | Generated benchmark reports and evidence |

## Documentation

- [Security model](docs/threat-model.md)
- [AWS permissions](docs/least-privilege.md)
- [Architecture decisions](docs/architecture/README.md)
- [IaC scanning setup](docs/iac-scanning.md)
- [Operations and troubleshooting](docs/operations-runbook.md)
- [Fixture environment](docs/test-environment.md)

## License

MIT. See [LICENSE](LICENSE).
