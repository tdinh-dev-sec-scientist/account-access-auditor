"""Provision the deliberately misconfigured test environment.

This module makes write calls. It is the *only* code in the repository that
does, and it is never imported by the auditor.

Backends
--------
``moto``  (default) An in-process emulation of the AWS APIs. The auditor talks
          to it through real boto3 clients and the real botocore request path,
          so collectors, pagination, error codes, and response shapes are all
          exercised; what is emulated is the service behind the endpoint.
``aws``   A real AWS account. Refuses to run unless
          ``AUDITOR_LAB_ALLOW_REAL_AWS=yes`` is set AND the caller passes
          ``--i-own-this-account``, because creating a public S3 bucket in the
          wrong account is not a recoverable mistake. Intended only for a
          dedicated, empty test account.

Time travel
-----------
An access key aged 400 days cannot be created on demand. Under ``moto`` the
provisioner backdates the emulator's stored timestamp directly, which is a
property of the fixture, not of the auditor: the auditor still reads the age
through ``iam:ListAccessKeys`` like any other key. Under ``aws`` there is no
equivalent, so age-dependent expectations depend on real elapsed time and the
provisioner says so rather than pretending otherwise.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import sys
from typing import Any

import boto3

from .resources import (
    ADMIN_STAR_STAR,
    ALL_PAB_OFF,
    ALL_PAB_ON,
    IAM_WILDCARD,
    ONLY_IGNORE_ACLS,
    SCOPED_LEAST_PRIVILEGE,
    SERVICE_WIDE,
    cloudtrail_bucket_policy,
    ip_conditioned_public_policy,
    public_read_policy,
    securetransport_only_policy,
)

log = logging.getLogger("lab.provision")

STALE_KEY_AGE_DAYS = 400
ROTATING_KEY_AGE_DAYS = 120
ROTATING_KEY_LAST_USED_DAYS = 5


# A throwaway password for an emulated login profile. It is not a secret: it
# exists only so the emulated user has a login profile for IAM-001 to find, and
# the same call against a real test account creates a password that is rotated
# or deleted with the lab. It is generated, never committed.
def _throwaway_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Lab!" + "".join(secrets.choice(alphabet) for _ in range(20)) + "9z"


class LabError(RuntimeError):
    """The lab could not be provisioned."""


# ------------------------------------------------------------- time travel --


def _backdate_access_key(
    username: str, key_id: str, age_days: int, last_used_days: int | None, backend: str
) -> bool:
    """Age an access key. Only possible on the moto backend."""
    if backend != "moto":
        log.warning(
            "Backend '%s' cannot backdate access key %s for %s; its age will be its real "
            "age, so age-dependent expectations (IAM-002, IAM-003) will not hold until "
            "enough time has passed.",
            backend,
            key_id,
            username,
        )
        return False

    from moto.core import DEFAULT_ACCOUNT_ID
    from moto.iam.models import AccessKeyLastUsed, iam_backends

    now = dt.datetime.now(dt.UTC)
    store = iam_backends[DEFAULT_ACCOUNT_ID]["global"]
    for key in store.users[username].access_keys:
        if key.access_key_id != key_id:
            continue
        key.create_date = now - dt.timedelta(days=age_days)
        if last_used_days is not None:
            key.last_used = AccessKeyLastUsed(
                timestamp=now - dt.timedelta(days=last_used_days),
                service="s3",
                region="us-east-1",
            )
        return True
    raise LabError(f"Access key {key_id} not found for {username}")  # pragma: no cover


# -------------------------------------------------------------------- IAM ---


def _provision_iam(session, backend: str, created: dict[str, Any]) -> None:
    iam = session.client("iam")

    # 1. Console user, no MFA, full-admin inline policy -> IAM-001 + IAM-004.
    iam.create_user(UserName="lab-admin-console-nomfa")
    iam.create_login_profile(UserName="lab-admin-console-nomfa", Password=_throwaway_password())
    iam.put_user_policy(
        UserName="lab-admin-console-nomfa",
        PolicyName="lab-full-admin",
        PolicyDocument=json.dumps(ADMIN_STAR_STAR),
    )

    # 2. Programmatic user, ancient never-used key -> IAM-006 + IAM-002 + IAM-003.
    iam.create_user(UserName="lab-svc-stale-keys")
    stale_key = iam.create_access_key(UserName="lab-svc-stale-keys")["AccessKey"]["AccessKeyId"]
    aged = _backdate_access_key("lab-svc-stale-keys", stale_key, STALE_KEY_AGE_DAYS, None, backend)
    created["stale_key_id"] = stale_key
    created["stale_key_backdated"] = aged

    # 3. Programmatic user, overdue but actively used key -> IAM-006 + IAM-002 only.
    iam.create_user(UserName="lab-svc-rotating")
    rotating_key = iam.create_access_key(UserName="lab-svc-rotating")["AccessKey"]["AccessKeyId"]
    _backdate_access_key(
        "lab-svc-rotating", rotating_key, ROTATING_KEY_AGE_DAYS, ROTATING_KEY_LAST_USED_DAYS, backend
    )
    created["rotating_key_id"] = rotating_key

    # 4. Console user WITH MFA plus a leftover Inactive key -> IAM-003 (LOW) only.
    iam.create_user(UserName="lab-contractor-offboarded")
    iam.create_login_profile(UserName="lab-contractor-offboarded", Password=_throwaway_password())
    _enable_mfa(iam, "lab-contractor-offboarded")
    inactive_key = iam.create_access_key(UserName="lab-contractor-offboarded")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="lab-contractor-offboarded", AccessKeyId=inactive_key, Status="Inactive")
    created["inactive_key_id"] = inactive_key

    # 5. Negative control: MFA, no keys, scoped policy containing a Deny.
    iam.create_user(UserName="lab-clean-user")
    iam.create_login_profile(UserName="lab-clean-user", Password=_throwaway_password())
    _enable_mfa(iam, "lab-clean-user")
    iam.put_user_policy(
        UserName="lab-clean-user",
        PolicyName="lab-scoped-read",
        PolicyDocument=json.dumps(SCOPED_LEAST_PRIVILEGE),
    )

    # 6. Group with a broad customer-managed policy -> IAM-005 at the group.
    broad = iam.create_policy(
        PolicyName="lab-broad-service-access",
        PolicyDocument=json.dumps(SERVICE_WIDE),
        Description="LAB ONLY: deliberately over-broad policy for scanner testing.",
    )["Policy"]["Arn"]
    iam.create_group(GroupName="lab-developers")
    iam.attach_group_policy(GroupName="lab-developers", PolicyArn=broad)
    iam.add_user_to_group(GroupName="lab-developers", UserName="lab-svc-rotating")
    iam.add_user_to_group(GroupName="lab-developers", UserName="lab-clean-user")

    # 7. Role with an inline iam:* policy -> IAM-005 at the role.
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName="lab-ci-deploy-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="lab-ci-deploy-role", PolicyName="lab-iam-wildcard", PolicyDocument=json.dumps(IAM_WILDCARD)
    )

    # 8. Negative control role.
    iam.create_role(RoleName="lab-readonly-role", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName="lab-readonly-role",
        PolicyName="lab-scoped-read",
        PolicyDocument=json.dumps(SCOPED_LEAST_PRIVILEGE),
    )


def _enable_mfa(iam, username: str) -> None:
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=f"{username}-mfa")
    iam.enable_mfa_device(
        UserName=username,
        SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )


# --------------------------------------------------------------------- S3 ---


def _bucket(s3, name: str, suffix: str) -> str:
    full = f"{name}-{suffix}" if suffix else name
    s3.create_bucket(Bucket=full)
    return full


def _encrypt(s3, bucket: str) -> None:
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )


def _provision_s3(session, account_id: str, suffix: str, created: dict[str, Any]) -> None:
    s3 = session.client("s3")
    names: dict[str, str] = {}

    # 1. Everything wrong at once.
    name = _bucket(s3, "lab-public-assets", suffix)
    names["lab-public-assets"] = name
    s3.put_bucket_acl(Bucket=name, ACL="public-read")
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(public_read_policy(name)))
    # No PAB configuration and no encryption configuration are the point here.

    # 2. Public principal, genuinely narrowed by aws:SourceIp -> MEDIUM.
    name = _bucket(s3, "lab-partner-share", suffix)
    names["lab-partner-share"] = name
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(ip_conditioned_public_policy(name)))
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_PAB_OFF)
    _encrypt(s3, name)

    # 3. Public principal with an aws:SecureTransport condition -> still CRITICAL.
    name = _bucket(s3, "lab-tls-only-public", suffix)
    names["lab-tls-only-public"] = name
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(securetransport_only_policy(name)))
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_PAB_OFF)
    _encrypt(s3, name)

    # 4. Public ACL neutralised by IgnorePublicAcls -> LOW, not silent.
    name = _bucket(s3, "lab-latent-acl", suffix)
    names["lab-latent-acl"] = name
    s3.put_bucket_acl(Bucket=name, ACL="public-read")
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ONLY_IGNORE_ACLS)
    _encrypt(s3, name)

    # 5. Public policy fully blocked by PAB -> LOW. Policy first: real AWS
    #    rejects a public policy once BlockPublicPolicy is on.
    name = _bucket(s3, "lab-blocked-public-policy", suffix)
    names["lab-blocked-public-policy"] = name
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(public_read_policy(name)))
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_PAB_ON)
    _encrypt(s3, name)

    # 6. Correct public-access posture, no encryption configuration -> S3-004 alone.
    name = _bucket(s3, "lab-unencrypted-logs", suffix)
    names["lab-unencrypted-logs"] = name
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_PAB_ON)

    # 7. Negative control: nothing wrong.
    name = _bucket(s3, "lab-clean-data", suffix)
    names["lab-clean-data"] = name
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_PAB_ON)
    _encrypt(s3, name)

    # 8. Negative control: CloudTrail delivery bucket with a *Service* principal.
    name = _bucket(s3, "lab-trail-logs", suffix)
    names["lab-trail-logs"] = name
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(cloudtrail_bucket_policy(name, account_id)))
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_PAB_ON)
    _encrypt(s3, name)

    created["buckets"] = names


# ------------------------------------------------------------- CloudTrail ---


def _provision_cloudtrail(session, trail_bucket: str, created: dict[str, Any]) -> None:
    ct = session.client("cloudtrail")
    ct.create_trail(
        Name="lab-single-region-trail",
        S3BucketName=trail_bucket,
        IsMultiRegionTrail=False,  # -> CT-002
        EnableLogFileValidation=False,  # -> CT-003
    )
    # Deliberately NOT started -> CT-004.
    created["trail"] = "lab-single-region-trail"


# ------------------------------------------------------------------ driver --


def provision(
    session,
    profile: str = "misconfigured",
    account_id: str = "123456789012",
    suffix: str = "",
    backend: str = "moto",
) -> dict[str, Any]:
    """Create the lab resources for ``profile``. Returns what was created."""
    created: dict[str, Any] = {"profile": profile, "backend": backend, "suffix": suffix}

    if profile == "misconfigured":
        _provision_iam(session, backend, created)
        _provision_s3(session, account_id, suffix, created)
        _provision_cloudtrail(session, created["buckets"]["lab-trail-logs"], created)
    elif profile == "no-trail":
        s3 = session.client("s3")
        name = _bucket(s3, "lab-notrail-data", suffix)
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_PAB_ON)
        _encrypt(s3, name)
        created["buckets"] = {"lab-notrail-data": name}
        # No trail is created: that is the whole point of this profile.
    else:
        raise LabError(f"Unknown lab profile '{profile}'")

    log.info("Provisioned lab profile '%s' on backend '%s'", profile, backend)
    return created


def build_lab_session(backend: str, region: str = "us-east-1"):
    """A plain, unguarded boto3 session. Write calls happen here, not in the auditor."""
    if backend == "moto":
        os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
        os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
        os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
        os.environ.setdefault("AWS_DEFAULT_REGION", region)
        os.environ.pop("AWS_PROFILE", None)
    return boto3.session.Session(region_name=region)


def guard_real_aws(confirmed: bool) -> None:
    """Two independent confirmations before touching a real account."""
    if os.environ.get("AUDITOR_LAB_ALLOW_REAL_AWS", "").lower() != "yes":
        raise LabError(
            "Refusing to provision against real AWS. This creates public S3 buckets and "
            "over-permissioned IAM principals. Set AUDITOR_LAB_ALLOW_REAL_AWS=yes and pass "
            "--i-own-this-account, and only ever point it at a dedicated, empty test account."
        )
    if not confirmed:
        raise LabError("Refusing to provision against real AWS without --i-own-this-account.")


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - operator entry point
    parser = argparse.ArgumentParser(
        prog="lab.provision",
        description="Create the deliberately misconfigured AWS test environment.",
    )
    parser.add_argument("--backend", choices=["moto", "aws"], default="moto")
    parser.add_argument("--profile", choices=["misconfigured", "no-trail"], default="misconfigured")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--suffix", default="", help="Suffix for globally-unique bucket names.")
    parser.add_argument("--i-own-this-account", action="store_true", dest="confirmed")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

    if args.backend == "aws":
        guard_real_aws(args.confirmed)
        session = boto3.session.Session(region_name=args.region)
        account_id = session.client("sts").get_caller_identity()["Account"]
        created = provision(session, args.profile, account_id, args.suffix, "aws")
        print(json.dumps(created, indent=2))
        return 0

    # The moto backend only exists inside its context manager, so provisioning
    # alone is not useful; lab/run_benchmark.py provisions and audits together.
    print(
        "The moto backend is in-process: resources exist only for the life of the "
        "mock. Run `python -m lab.run_benchmark` to provision and audit in one process."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
