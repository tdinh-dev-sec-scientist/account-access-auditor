"""The Lambda bundle must contain every file the Stage 2 handlers read.

Only the packages scripts/package_phase3_lambdas.py bundles are copied into an
empty directory. A subprocess then runs the production data path from there
against moto: real rules scan an emulated demo account, the private store
persists the report, the publisher Lambda handler redacts and publishes it,
and the public API Lambda handler serves it to a signed-in caller. An
unusable pseudonym key must fail publication and leave the published
snapshot untouched.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from scripts.package_phase3_lambdas import PACKAGES

ROOT = Path(__file__).resolve().parents[1]

PIPELINE = r"""
import base64, json, os, sys
app, reports_path = sys.argv[1], sys.argv[2]
sys.path.insert(0, app)
reports = json.loads(open(reports_path).read())
os.environ.update({
    "AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
})
import boto3
from moto import mock_aws

with mock_aws():
    from phase3 import public_api, publisher
    from phase3.private_snapshot_store import PrivateSnapshotStore

    assert publisher.__file__.startswith(app), publisher.__file__
    aws = boto3.session.Session(region_name="us-east-1")
    s3, ddb = aws.client("s3"), aws.resource("dynamodb")
    account = aws.client("sts").get_caller_identity()["Account"]
    for bucket in ("private", "public"):
        s3.create_bucket(Bucket=bucket)

    def table(name, keys, indexes=()):
        attrs = {k for k, _ in keys} | {k for _, ks in indexes for k, _ in ks}
        spec = dict(
            TableName=name, BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": k, "KeyType": t} for k, t in keys],
            AttributeDefinitions=[{"AttributeName": a, "AttributeType": "S"} for a in sorted(attrs)],
        )
        if indexes:
            spec["GlobalSecondaryIndexes"] = [
                {"IndexName": n, "KeySchema": [{"AttributeName": k, "KeyType": t} for k, t in ks],
                 "Projection": {"ProjectionType": "ALL"}} for n, ks in indexes
            ]
        return ddb.create_table(**spec)

    runs = table("private-runs", [("account_id", "HASH"), ("sort_key", "RANGE")], [
        ("status-index", [("status_pk", "HASH"), ("status_sk", "RANGE")]),
        ("scan-run-index", [("scan_run_id", "HASH")]),
    ])
    table("public-index", [("pk", "HASH"), ("sk", "RANGE")])
    secrets = aws.client("secretsmanager")
    secret_arn = secrets.create_secret(
        Name="vorrin/phase3/public-pseudonym-hmac", SecretString=base64.b64encode(os.urandom(32)).decode()
    )["ARN"]

    store = PrivateSnapshotStore(bucket_name="private", account_id=account, s3_client=s3, run_index_table=runs)
    receipt = store.persist(reports[0])

    os.environ.update({
        "PHASE3_TARGET_ACCOUNT_ID": account,
        "PHASE3_PRIVATE_SNAPSHOT_BUCKET": "private",
        "PHASE3_PUBLIC_RESULTS_BUCKET": "public",
        "PHASE3_PUBLIC_INDEX_TABLE": "public-index",
        "PHASE3_PSEUDONYM_SECRET_ARN": secret_arn,
        "PHASE3_ACCESS_MODE": "invite_only",
        "PHASE3_COGNITO_ISSUER": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123",
        "PHASE3_COGNITO_CLIENT_ID": "1example23456789abcdefghij",
        "PHASE3_FEATURE_TABLE": "",
    })
    published = publisher.lambda_handler({"receipt": receipt}, None)
    latest = ddb.Table("public-index").get_item(Key={"pk": "demo", "sk": "LATEST"})["Item"]
    body = s3.get_object(Bucket="public", Key=latest["snapshot_key"])["Body"].read()

    claims = {
        "iss": os.environ["PHASE3_COGNITO_ISSUER"], "aud": os.environ["PHASE3_COGNITO_CLIENT_ID"],
        "token_use": "id", "sub": "4f1c6f7e-9e4a-4b9a-8c39-1a2b3c4d5e6f",
    }
    statuses = {}
    for route in ("latest", "runs", "findings", "drift"):
        for method in ("GET", "HEAD", "POST"):
            event = {"httpMethod": method, "path": f"/api/{route}", "queryStringParameters": None,
                     "requestContext": {"authorizer": {"claims": claims}}}
            statuses[f"{method} {route}"] = public_api.lambda_handler(event, None)["statusCode"]
    anonymous = public_api.lambda_handler({"httpMethod": "GET", "path": "/api/latest"}, None)["statusCode"]

    secrets.put_secret_value(SecretId=secret_arn, SecretString="!not-base64!")
    second = store.persist(reports[1])
    try:
        publisher.lambda_handler({"receipt": second}, None)
        failed = False
    except publisher.PublicationError:
        failed = True
    paused = publisher.lambda_handler({"kind": "publication_failure", "completed_at": "2030-01-01T00:00:00+00:00"}, None)
    after = ddb.Table("public-index").get_item(Key={"pk": "demo", "sk": "LATEST"})["Item"]
    after_body = s3.get_object(Bucket="public", Key=after["snapshot_key"])["Body"].read()

    print(json.dumps({
        "receipt_status": receipt["status"],
        "published": bool(published),
        "public_has_account_id": account.encode() in body,
        "statuses": statuses,
        "anonymous": anonymous,
        "failed_with_bad_key": failed,
        "paused": paused["status"],
        "latest_unchanged": after["snapshot_key"] == latest["snapshot_key"] and after_body == body,
        "public_body": body.decode(),
        "account": account,
    }))
"""


def _scan_reports() -> list[dict]:
    """Two real scans of a moto account (moto's default account ID), as the container produces."""
    import boto3
    from moto import mock_aws

    from auditor import fleet_scan
    from auditor.config import defaults
    from auditor.fleet import FleetConfig, TargetAccount

    with mock_aws():
        aws = boto3.session.Session(region_name="us-east-1")
        aws.client("s3").create_bucket(Bucket="demo-a")
        aws.client("iam").create_user(UserName="alice")
        account = aws.client("sts").get_caller_identity()["Account"]
        config = FleetConfig(
            accounts=(TargetAccount(account, f"arn:aws:iam::{account}:role/AccountAccessAuditorReadOnly"),),
            regions=("us-east-1",),
            services=("iam", "s3", "cloudtrail"),
        )
        original = fleet_scan._assume_role
        fleet_scan._assume_role = lambda _s, **kw: (
            boto3.session.Session(region_name=kw["region_name"]),
            None,
        )
        try:
            return [fleet_scan.run_fleet_scan(config, defaults(), aws, run_id=f"run-{n}") for n in (1, 2)]
        finally:
            fleet_scan._assume_role = original


def test_stage2_handlers_run_from_only_the_lambda_bundle(tmp_path):
    reports = _scan_reports()
    assert all(report["contract"]["scan_run"]["status"] in {"PASS", "FAIL"} for report in reports)
    reports_path = tmp_path / "reports.json"
    reports_path.write_text(json.dumps(reports))
    app = tmp_path / "bundle"
    for package in PACKAGES:
        shutil.copytree(ROOT / package, app / package, ignore=shutil.ignore_patterns("__pycache__"))
    result = subprocess.run(
        [sys.executable, "-c", PIPELINE, str(app), str(reports_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    assert outcome["receipt_status"] in {"PASS", "FAIL"}
    assert outcome["published"] is True
    assert outcome["public_has_account_id"] is False
    for route in ("latest", "runs", "findings", "drift"):
        assert outcome["statuses"][f"GET {route}"] == 200, outcome["statuses"]
        assert outcome["statuses"][f"HEAD {route}"] == 200, outcome["statuses"]
        assert outcome["statuses"][f"POST {route}"] == 405, outcome["statuses"]
    assert outcome["anonymous"] == 401
    assert outcome["failed_with_bad_key"] is True
    assert outcome["paused"] == "PUBLICATION_PAUSED"
    assert outcome["latest_unchanged"] is True
    # The Stage 2 collector's leak scan must find nothing in a real published snapshot.
    from scripts.collect_phase3_stage2_evidence import count_leaks

    private_values = [outcome["account"], "demo-a", "AccountAccessAuditorReadOnly"]
    assert count_leaks([outcome["public_body"].encode()], private_values) == {}
