# Multi-account scans and drift history

`fleet-scan` assumes a configured `AccountAccessAuditorReadOnly` role in each
target account. It reads IAM and S3 once per account, and reads CloudTrail in
each configured region. Every target session gets the same runtime read-only
guard as a single-account scan. Account and region failures remain visible as
incomplete coverage and produce an `UNKNOWN` result; the scan continues with
the remaining configured targets.

## Configure target roles

Create the target role through your organization's existing account-provisioning
process. The role must be named `AccountAccessAuditorReadOnly`. Attach only the
IAM, S3, and CloudTrail read statements needed by the configured services. The
source principal that runs the auditor needs `sts:AssumeRole` for this exact
role name; `python -m auditor.cli generate-policy` includes that scoped
statement. Use a trust policy restricted to the source auditor role. If your
organization uses an external ID, put the ID in a secret store and expose it to
the process as an `AUDITOR_EXTERNAL_ID_*` environment variable. Names containing
credential labels such as `SECRET`, `TOKEN`, `PASSWORD`, or `PRIVATE_KEY` are
rejected so fleet config cannot forward an unrelated credential to STS.

`examples/fleet.yaml` shows the supported target configuration. It contains no
credentials or external-ID values. The loader rejects duplicate YAML keys,
unknown fields, duplicate accounts or regions, account/role mismatches, and
external IDs embedded in the file.

```bash
export AUDITOR_EXTERNAL_ID_PROD='value-from-your-secret-store'
python -m auditor.cli fleet-scan \
  --fleet-config examples/fleet.yaml \
  --profile auditor-source \
  --history-dir "$HOME/.local/state/account-access-auditor/history" \
  --fail-on high
```

The fleet report is written to stdout as JSON. Its snapshot is also stored in a
private local SQLite database (`0700` directory, `0600` database). No scan data
is written to an AWS service. The history store keeps immutable runs and
computes `new`, `persistent`, `changed`, `resolved`, and `unknown` transitions
per account, service, and region. An incomplete scope cannot resolve findings
or replace the last complete baseline for that scope.

## View history

```bash
python -m auditor.cli history \
  --history-dir "$HOME/.local/state/account-access-auditor/history"

python -m auditor.cli history \
  --history-dir "$HOME/.local/state/account-access-auditor/history" \
  --format html --output reports/fleet-history.html
```

The JSON view contains recent run summaries and finding transitions. The static
HTML dashboard shows recent scans and drift without JavaScript or external
network requests. Exported files receive `0600` permissions.

## Schedule scans on the host

The scheduled runner uses `fcntl` locking to skip overlapping invocations and
targets Unix-like hosts (Linux or macOS). Set these environment variables in
the scheduler's environment:

- `AUDITOR_FLEET_CONFIG`: path to the fleet YAML file.
- `AUDITOR_HISTORY_DIR`: private local snapshot directory.
- `AWS_PROFILE`: optional named profile for source credentials.
- `AUDITOR_APP_CONFIG`: optional auditor rules configuration.
- `AUDITOR_FAIL_ON`: optional severity gate (`critical`, `high`, `medium`, `low`, or `info`).

Example cron entry (replace the project, virtual environment, and config paths):

```cron
15 2 * * * umask 077; AUDITOR_FLEET_CONFIG=/etc/account-access-auditor/fleet.yaml AUDITOR_HISTORY_DIR=/var/lib/account-access-auditor/history AWS_PROFILE=auditor-source /opt/account-access-auditor/.venv/bin/python /opt/account-access-auditor/scripts/scheduled_fleet_scan.py >/dev/null
```

The host scheduler is deliberate: setting up EventBridge, Step Functions, S3,
or DynamoDB would require AWS resource writes. This project keeps the AWS
execution path read-only and stores history locally; deploy a separate,
organization-managed scheduler only if its provisioning and storage writes are
approved outside the auditor.

## Optional IAM Access Analyzer validation

Validate one local IAM policy without enabling another permission for normal
scans:

```bash
python -m auditor.cli generate-policy \
  --include-optional-access-analyzer > /tmp/auditor-access-analyzer-policy.json
python -m auditor.cli validate-access-analyzer policies/auditor-readonly-policy.json \
  --profile auditor-source --region us-east-1 --fail-on high
```

Install the generated optional permission only on a principal that needs this
command. The default policy excludes `access-analyzer:ValidatePolicy`; the
validation session adds only that API operation to the runtime allowlist. This
API evaluates the supplied policy document and does not create an analyzer or
modify account resources.
