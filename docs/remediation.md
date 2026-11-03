# Review-bound IaC remediation

Remediation stays review-first. The auditor can render a deterministic patch,
open a proposal pull request from a manually dispatched trusted workflow, and
test an approved patch against a disposable local copy. It never edits the
source tree or applies changes to AWS.

## Approved Stage 6 plan amendment (2026-11-02)

The plan and its controlling [read-only Stage 6 amendment](phase2-stage6-amendment.md)
preserve the project's AWS read-only boundary. AWS sandbox apply is not
implemented or claimed. This implementation applies an approved patch only to
a private temporary local copy and adds no AWS write permissions, APIs, or
apply role. The local simulation is not AWS remediation; it satisfies the
amended Phase 2 Stage 6 acceptance when the mandatory rescan and safety checks
pass.

## Plan format

Plans are strict JSON. An edit is an exact text replacement in a supported IaC
file; the original text must occur exactly once. Paths cannot be absolute,
contain traversal or wildcards, or target application code. Plans name the
finding fingerprints they intend to resolve.

```json
{
  "schema_version": "1.0.0",
  "target": "sandbox",
  "review": {"status": "PENDING"},
  "target_fingerprints": ["a1b2c3d4e5f60718"],
  "operations": [
    {
      "op": "replace_text",
      "path": "main.tf",
      "before": "acl = \"public-read\"",
      "after": "acl = \"private\""
    }
  ]
}
```

## Preview and create a pull request

Generate a preview from the unchanged base source. The preview contains the
patch and a SHA-256 digest that binds the change to the source tree.

```bash
python -m auditor.cli remediation-preview \
  --source infra \
  --plan /tmp/remediation-plan.json \
  > /tmp/remediation-preview.json
```

Put the plan on a same-repository proposal branch. From the default branch,
manually dispatch the [proposal workflow](../.github/workflows/remediation-pr.yml)
with that branch, the plan path, the IaC source directory, and a reviewer login.
The trusted workflow reads the plan as data, creates a separate patch branch,
and opens a pull request with the preview digest in its body. Its only write
permissions are GitHub `contents` and `pull-requests`; it has no AWS credentials
or AWS permissions. It does not merge or deploy the pull request.

After approval, set the plan's `review` object to include the reviewer login,
the pull request URL, and the preview's `preview_sha256`:

```json
{
  "status": "APPROVED",
  "reviewer": "security-lead",
  "reference": "https://github.com/example/repository/pull/42",
  "preview_sha256": "<64-character digest from the preview>"
}
```

## Local sandbox simulation and mandatory rescan

Use the original base source tree, the approved plan, and a read-only GitHub
token with pull-request read access. The command checks that the pull request is
open, its approval decision is `APPROVED`, the named reviewer's latest review
approved the current pull-request head, and the pull-request body contains the
matching digest. Review lookup uses read-only [`gh pr view`](https://cli.github.com/manual/gh_pr_view)
and paginated [`gh api`](https://cli.github.com/manual/gh_api) calls. The token
is passed only to those GitHub CLI subprocesses. Missing or stale review data
blocks the operation.

```bash
export GH_TOKEN="<read-only GitHub token>"
python -m auditor.cli remediation-sandbox \
  --source /path/to/unchanged/base/infra \
  --plan /tmp/approved-remediation-plan.json \
  --output-dir /tmp/remediation-evidence \
  --fail-on HIGH \
  --confirm-sandbox
unset GH_TOKEN
```

The plan is applied only in a temporary copy. A full IaC rescan is mandatory;
the command blocks if a targeted finding remains, the scan is incomplete or
fails its gate, the source changed after review, or the pull-request approval
cannot be verified. It writes a private patch, rescan report, and result record
only after a passing rescan. The output directory and files deny group and
other access.

The auditor accepts only `target: sandbox`. It does not invoke Terraform,
Kubernetes, AWS APIs, or cloud apply commands. AWS assessment stays read-only;
the sandbox is a temporary local copy. Production changes remain in the
reviewed pull request and normal deployment approval process.
