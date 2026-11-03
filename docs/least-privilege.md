# The auditor's own IAM policy

`policies/auditor-readonly-policy.json` is **generated from the code**, not
maintained by hand:

```bash
python -m auditor.cli generate-policy --write
```

The generator reads `auditor/permissions.py`, which declares every AWS API
operation the tool is allowed to make, along with the IAM action that authorises
it, the resource scope that action supports, and why the tool needs it. Calls
either read target state or perform explicitly non-mutating STS role assumption
or optional Access Analyzer policy validation. A test
(`tests/test_security_properties.py::test_committed_policy_matches_the_generated_one`)
fails if the committed file and the code disagree, so the policy cannot drift
behind a new collector.

## The chain

```
collector source            auditor/permissions.py         generated policy
────────────────            ──────────────────────         ────────────────
client.list_users()   →     iam:ListUsers                →  AuditorListPrincipals
                            resource: *                     Resource: "*"

client.get_bucket_acl()  →  s3:GetBucketAcl              →  AuditorReadBuckets
                            resource: arn:aws:s3:::*        Resource: "arn:aws:s3:::*"
```

Print the whole table:

```bash
python -m auditor.cli list-permissions
python -m auditor.cli list-permissions --json
```

## Why some statements are still `Resource: "*"`

Four of the eleven default statements use `"*"`, and each is a limitation of the AWS API
rather than a shortcut:

| Statement | Actions | Why the resource cannot be narrowed |
| --- | --- | --- |
| `AuditorIdentity` | `sts:GetCallerIdentity` | The action has no resource; AWS documents it as always allowed and it cannot carry a resource-level condition. |
| `AuditorAssumeTargetRole` | `sts:AssumeRole` | Obtains temporary credentials for the configured target-role name without modifying target resources. |
| `AuditorListPrincipals` | `iam:ListUsers`, `iam:ListGroups`, `iam:ListRoles` | List operations enumerate an account-level collection. IAM does not support resource-level permissions for them. |
| `AuditorListBuckets` | `s3:ListAllMyBuckets` | Account-scoped: it returns the bucket list itself, so there is no bucket to scope it to. |
| `AuditorReadCloudTrail` | `cloudtrail:DescribeTrails` | Enumerates trails across the region; CloudTrail does not support resource-level permissions on it. |

The remaining seven statements are scoped to a resource pattern:
`arn:aws:iam::*:role/AccountAccessAuditorReadOnly`,
`arn:aws:iam::*:user/*`, `arn:aws:iam::*:group/*`, `arn:aws:iam::*:role/*`,
`arn:aws:iam::*:policy/*` plus `arn:aws:iam::aws:policy/*`, `arn:aws:s3:::*`,
and `arn:aws:cloudtrail:*:*:trail/*`.

**Tightening further.** The account segment is left as `*` because the file is
published as a template. Restrict the caller's `sts:AssumeRole` permission and
the target role trust policy to the configured account IDs and source principal.
Attach the service read statements to the target role; do not grant that role
permission to assume other roles.

## What the policy does not contain

No action in the policy is a wildcard. There is no `iam:*`, no `s3:*`, no `"*"`,
and no AWS resource-modifying action. The default policy has 31 explicit
operations, including non-mutating `sts:AssumeRole`. Optional
`access-analyzer:ValidatePolicy` is excluded unless requested. These claims are
asserted by tests:

- `test_generated_policy_has_no_wildcard_action` — no `*` and no `service:*`;
- `test_declared_inventory_contains_only_read_operations` — every declared
  operation reads target state or is an explicitly allowed non-mutating
  authentication/validation call;
- `test_no_write_operation_appears_in_auditor_source` — the set of write
  operations is derived from **botocore's own service models**, and no source
  file under `auditor/` references one;
- `test_inventory_has_no_permission_the_rules_do_not_need` — nothing is granted
  "just in case".

## The self-audit

The auditor runs its own wildcard-policy rules against this policy:

```bash
python -m auditor.cli validate-policy
python -m auditor.cli validate-policy --json
```

```
Self-audit of policies/auditor-readonly-policy.json
  statements:                  11
  IAM-004 (Action * on *):     PASS
  IAM-005 (service-wide on *): PASS
  declared calls read-only:    PASS (All declared API operations are read-only.)

RESULT: PASS
```

The result is meaningful only because the detector was not weakened to produce
it. `tests/test_cli.py::test_validate_policy_fails_on_an_admin_policy` and
`::test_validate_policy_fails_on_a_service_wide_policy` feed the same checker a
policy that *should* fail and assert that it does. The auditor's policy passes
because it enumerates explicit read and non-mutating authentication actions,
not because the rule stopped looking.

## Optional Access Analyzer permission

The default policy excludes `access-analyzer:ValidatePolicy`. To include it for
a principal that needs the separate local-policy validation command, run:

```bash
python -m auditor.cli generate-policy --include-optional-access-analyzer
```

That validation session permits only the additional API operation and continues
to reject analyzer creation and every other undeclared AWS operation.

## Runtime enforcement

Least privilege at the IAM layer is the primary control. The tool adds a second
one: `auditor/readonly.py` registers a botocore `before-call` hook that rejects
any operation not present in the declared inventory, before the request is
signed and sent.

```python
>>> session, guard = build_session(region="us-east-1")
>>> session.client("iam").create_user(UserName="x")
ReadOnlyViolation: Blocked 'iam:CreateUser': the auditor is read-only ...
```

It is an allowlist rather than a verb heuristic, so it also blocks a *read* call
the project never declared — which catches scope creep as well as writes.
