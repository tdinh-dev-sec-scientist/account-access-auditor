"""Offline fixture cases for the four S3 rules."""

from __future__ import annotations

from tests.builders import (
    ALL_PAB_OFF,
    bucket,
    bucket_policy_doc,
    pab,
    private_acl_grant,
    public_acl_grant,
    s3_state,
)

from . import Case, Expected

PUBLIC_POLICY = bucket_policy_doc()
PUBLIC_POLICY_DICT_PRINCIPAL = bucket_policy_doc(principal={"AWS": "*"})
PUBLIC_POLICY_PRINCIPAL_LIST = bucket_policy_doc(principal={"AWS": ["*", "arn:aws:iam::123456789012:root"]})
IP_CONDITIONED = bucket_policy_doc(
    principal={"AWS": "*"},
    condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
)
TLS_ONLY = bucket_policy_doc(condition={"Bool": {"aws:SecureTransport": "true"}})
ORG_CONDITIONED = bucket_policy_doc(
    principal={"AWS": "*"},
    condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
)
SERVICE_PRINCIPAL = bucket_policy_doc(principal={"Service": "cloudtrail.amazonaws.com"})
ACCOUNT_PRINCIPAL = bucket_policy_doc(principal={"AWS": "arn:aws:iam::123456789012:root"})
PUBLIC_DENY = bucket_policy_doc(principal="*", effect="Deny")
NOT_PRINCIPAL = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EveryoneExceptOne",
            "Effect": "Allow",
            "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::test-bucket/*",
        }
    ],
}

CASES = (
    # ------------------------------------------------------------- S3-001 ---
    Case(
        case_id="s3-001-all-protections-on",
        service="s3",
        category="clean",
        covers=("S3-001",),
        description="All four Block Public Access settings enabled produces nothing.",
        data=s3_state(bucket("locked")),
    ),
    Case(
        case_id="s3-001-no-pab-configuration",
        service="s3",
        category="vulnerable",
        covers=("S3-001",),
        description="No Public Access Block configuration at all is MEDIUM.",
        data=s3_state(bucket("unset", public_access_block=None)),
        expected=(Expected("S3-001", "unset", "MEDIUM"),),
    ),
    Case(
        case_id="s3-001-one-setting-off",
        service="s3",
        category="edge",
        covers=("S3-001",),
        description="A single disabled setting is enough to fire; the rule requires all four.",
        data=s3_state(bucket("partial", public_access_block=pab(RestrictPublicBuckets=False))),
        expected=(Expected("S3-001", "partial", "MEDIUM"),),
    ),
    Case(
        case_id="s3-001-all-settings-off",
        service="s3",
        category="vulnerable",
        covers=("S3-001",),
        description="A configuration with all four settings explicitly false fires once, not four times.",
        data=s3_state(bucket("wide-open", public_access_block=dict(ALL_PAB_OFF))),
        expected=(Expected("S3-001", "wide-open", "MEDIUM"),),
    ),
    Case(
        case_id="s3-001-pab-unreadable",
        service="s3",
        category="edge",
        covers=("S3-001",),
        description="Denied GetPublicAccessBlock must not be reported as an absent configuration.",
        data=s3_state(bucket("opaque", public_access_block=None, public_access_block_known=False)),
    ),
    Case(
        case_id="s3-001-partial-keys-in-response",
        service="s3",
        category="malformed",
        covers=("S3-001",),
        description="A PAB response missing keys treats the absent ones as disabled.",
        data=s3_state(bucket("sparse", public_access_block={"BlockPublicAcls": True})),
        expected=(Expected("S3-001", "sparse", "MEDIUM"),),
    ),
    # ------------------------------------------------------------- S3-002 ---
    Case(
        case_id="s3-002-allusers-grant-unprotected",
        service="s3",
        category="vulnerable",
        covers=("S3-001", "S3-002"),
        description="An AllUsers ACL grant with protections off is CRITICAL.",
        data=s3_state(
            bucket("public-acl", public_access_block=dict(ALL_PAB_OFF), acl_grants=[public_acl_grant()])
        ),
        expected=(
            Expected("S3-001", "public-acl", "MEDIUM"),
            Expected("S3-002", "public-acl", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-002-authenticatedusers-grant",
        service="s3",
        category="vulnerable",
        covers=("S3-002",),
        description="AuthenticatedUsers means any AWS account holder and is treated as public.",
        data=s3_state(
            bucket(
                "cross-account",
                public_access_block=pab(IgnorePublicAcls=False),
                acl_grants=[public_acl_grant("AuthenticatedUsers", "WRITE")],
            )
        ),
        expected=(
            Expected("S3-001", "cross-account", "MEDIUM"),
            Expected("S3-002", "cross-account", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-002-ignored-by-pab",
        service="s3",
        category="severity",
        covers=("S3-002",),
        description="IgnorePublicAcls neutralises the grant today, so it is LOW rather than dropped.",
        data=s3_state(
            bucket("latent", public_access_block=pab(BlockPublicAcls=False), acl_grants=[public_acl_grant()])
        ),
        expected=(Expected("S3-001", "latent", "MEDIUM"), Expected("S3-002", "latent", "LOW")),
    ),
    Case(
        case_id="s3-002-blockpublicacls-does-not-neutralise",
        service="s3",
        category="edge",
        covers=("S3-002",),
        description="BlockPublicAcls stops new grants but does not ignore existing ones, so this stays CRITICAL.",
        data=s3_state(
            bucket(
                "still-public",
                public_access_block=pab(IgnorePublicAcls=False),
                acl_grants=[public_acl_grant()],
            )
        ),
        expected=(
            Expected("S3-001", "still-public", "MEDIUM"),
            Expected("S3-002", "still-public", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-002-private-grants-only",
        service="s3",
        category="clean",
        covers=("S3-002",),
        description="A canonical-user ACL grant is a named identity, not the public.",
        data=s3_state(bucket("owned", acl_grants=[private_acl_grant()])),
    ),
    Case(
        case_id="s3-002-mixed-grants",
        service="s3",
        category="edge",
        covers=("S3-002",),
        description="One public grant among several private ones still fires, once.",
        data=s3_state(
            bucket(
                "mixed",
                public_access_block=dict(ALL_PAB_OFF),
                acl_grants=[private_acl_grant(), public_acl_grant(), private_acl_grant("READ")],
            )
        ),
        expected=(Expected("S3-001", "mixed", "MEDIUM"), Expected("S3-002", "mixed", "CRITICAL")),
    ),
    Case(
        case_id="s3-002-two-public-grants-one-finding",
        service="s3",
        category="edge",
        covers=("S3-002",),
        description="READ and WRITE grants to AllUsers are one bucket-level finding, not two.",
        data=s3_state(
            bucket(
                "double",
                public_access_block=dict(ALL_PAB_OFF),
                acl_grants=[public_acl_grant("AllUsers", "READ"), public_acl_grant("AllUsers", "WRITE")],
            )
        ),
        expected=(Expected("S3-001", "double", "MEDIUM"), Expected("S3-002", "double", "CRITICAL")),
    ),
    Case(
        case_id="s3-002-no-acl-grants",
        service="s3",
        category="edge",
        covers=("S3-002",),
        description="An empty ACL grant list produces nothing.",
        data=s3_state(bucket("empty-acl", acl_grants=[])),
    ),
    # ------------------------------------------------------------- S3-003 ---
    Case(
        case_id="s3-003-unconditional-public-policy",
        service="s3",
        category="vulnerable",
        covers=("S3-003",),
        description='An unconditional Principal "*" Allow is CRITICAL.',
        data=s3_state(
            bucket(
                "open-policy",
                public_access_block=dict(ALL_PAB_OFF),
                bucket_policy=PUBLIC_POLICY,
                policy_is_public=True,
            )
        ),
        expected=(
            Expected("S3-001", "open-policy", "MEDIUM"),
            Expected("S3-003", "open-policy", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-003-dict-principal-form",
        service="s3",
        category="edge",
        covers=("S3-003",),
        description='Principal {"AWS": "*"} is the same anonymous grant as Principal "*".',
        data=s3_state(
            bucket(
                "dict-form", public_access_block=dict(ALL_PAB_OFF), bucket_policy=PUBLIC_POLICY_DICT_PRINCIPAL
            )
        ),
        expected=(
            Expected("S3-001", "dict-form", "MEDIUM"),
            Expected("S3-003", "dict-form", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-003-principal-list-containing-star",
        service="s3",
        category="edge",
        covers=("S3-003",),
        description='A principal list containing "*" alongside a real ARN is still public.',
        data=s3_state(
            bucket(
                "list-form", public_access_block=dict(ALL_PAB_OFF), bucket_policy=PUBLIC_POLICY_PRINCIPAL_LIST
            )
        ),
        expected=(
            Expected("S3-001", "list-form", "MEDIUM"),
            Expected("S3-003", "list-form", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-003-not-principal",
        service="s3",
        category="edge",
        covers=("S3-003",),
        description="Allow with NotPrincipal grants everyone except one identity, which includes anonymous callers.",
        data=s3_state(
            bucket("not-principal", public_access_block=dict(ALL_PAB_OFF), bucket_policy=NOT_PRINCIPAL)
        ),
        expected=(
            Expected("S3-001", "not-principal", "MEDIUM"),
            Expected("S3-003", "not-principal", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-003-ip-condition-downgrades",
        service="s3",
        category="severity",
        covers=("S3-003",),
        description="aws:SourceIp genuinely narrows who can call, so the finding is MEDIUM for review.",
        data=s3_state(bucket("partner", public_access_block=dict(ALL_PAB_OFF), bucket_policy=IP_CONDITIONED)),
        expected=(
            Expected("S3-001", "partner", "MEDIUM"),
            Expected("S3-003", "partner", "MEDIUM"),
        ),
    ),
    Case(
        case_id="s3-003-org-condition-downgrades",
        service="s3",
        category="severity",
        covers=("S3-003",),
        description="aws:PrincipalOrgID confines the grant to one organisation, so MEDIUM.",
        data=s3_state(
            bucket("org-only", public_access_block=dict(ALL_PAB_OFF), bucket_policy=ORG_CONDITIONED)
        ),
        expected=(
            Expected("S3-001", "org-only", "MEDIUM"),
            Expected("S3-003", "org-only", "MEDIUM"),
        ),
    ),
    Case(
        case_id="s3-003-securetransport-does-not-downgrade",
        service="s3",
        category="edge",
        covers=("S3-003",),
        description="aws:SecureTransport only requires HTTPS, so a TLS-only condition stays CRITICAL.",
        data=s3_state(bucket("tls-public", public_access_block=dict(ALL_PAB_OFF), bucket_policy=TLS_ONLY)),
        expected=(
            Expected("S3-001", "tls-public", "MEDIUM"),
            Expected("S3-003", "tls-public", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-003-blocked-by-pab",
        service="s3",
        category="severity",
        covers=("S3-003",),
        description="A public policy with all four PAB settings on is LOW: latent, not live.",
        data=s3_state(bucket("blocked", bucket_policy=PUBLIC_POLICY)),
        expected=(Expected("S3-003", "blocked", "LOW"),),
    ),
    Case(
        case_id="s3-003-restrictpublicbuckets-alone-blocks",
        service="s3",
        category="edge",
        covers=("S3-003",),
        description="RestrictPublicBuckets alone is enough to downgrade the policy finding to LOW.",
        data=s3_state(
            bucket(
                "restricted",
                public_access_block=pab(
                    BlockPublicAcls=False, IgnorePublicAcls=False, BlockPublicPolicy=False
                ),
                bucket_policy=PUBLIC_POLICY,
            )
        ),
        expected=(
            Expected("S3-001", "restricted", "MEDIUM"),
            Expected("S3-003", "restricted", "LOW"),
        ),
    ),
    Case(
        case_id="s3-003-service-principal-not-public",
        service="s3",
        category="clean",
        covers=("S3-003",),
        description="A CloudTrail service principal is a named service, not the public.",
        data=s3_state(bucket("trail-logs", bucket_policy=SERVICE_PRINCIPAL)),
    ),
    Case(
        case_id="s3-003-account-principal-not-public",
        service="s3",
        category="clean",
        covers=("S3-003",),
        description="A specific account-root principal is not public.",
        data=s3_state(bucket("shared", bucket_policy=ACCOUNT_PRINCIPAL)),
    ),
    Case(
        case_id="s3-003-public-deny-not-a-grant",
        service="s3",
        category="clean",
        covers=("S3-003",),
        description='Deny with Principal "*" is a restriction and must not be reported as exposure.',
        data=s3_state(bucket("deny-all", bucket_policy=PUBLIC_DENY)),
    ),
    Case(
        case_id="s3-003-no-policy",
        service="s3",
        category="clean",
        covers=("S3-003",),
        description="A bucket with no policy at all produces nothing.",
        data=s3_state(bucket("no-policy", bucket_policy=None)),
    ),
    Case(
        case_id="s3-003-policy-status-public-only",
        service="s3",
        category="edge",
        covers=("S3-003",),
        description="GetBucketPolicyStatus reporting IsPublic still fires even when the document is unreadable.",
        data=s3_state(
            bucket(
                "status-only",
                public_access_block=dict(ALL_PAB_OFF),
                bucket_policy=None,
                policy_is_public=True,
            )
        ),
        expected=(
            Expected("S3-001", "status-only", "MEDIUM"),
            Expected("S3-003", "status-only", "CRITICAL"),
        ),
    ),
    Case(
        case_id="s3-003-unparsed-policy",
        service="s3",
        category="malformed",
        covers=("S3-003",),
        description="A bucket policy that would not parse yields no statements rather than a crash.",
        data=s3_state(
            bucket("garbled", public_access_block=dict(ALL_PAB_OFF), bucket_policy={"_unparsed": "{not json"})
        ),
        expected=(Expected("S3-001", "garbled", "MEDIUM"),),
    ),
    # ------------------------------------------------------------- S3-004 ---
    Case(
        case_id="s3-004-no-encryption-config",
        service="s3",
        category="vulnerable",
        covers=("S3-004",),
        description="No bucket-level default encryption configuration is MEDIUM.",
        data=s3_state(bucket("unencrypted", encryption_configured=False)),
        expected=(Expected("S3-004", "unencrypted", "MEDIUM"),),
    ),
    Case(
        case_id="s3-004-encryption-configured",
        service="s3",
        category="clean",
        covers=("S3-004",),
        description="An explicit SSE-S3 configuration produces nothing.",
        data=s3_state(bucket("encrypted", encryption_configured=True)),
    ),
    Case(
        case_id="s3-004-encryption-unreadable",
        service="s3",
        category="edge",
        covers=("S3-004",),
        description="Denied GetBucketEncryption is unknown, not absent, so the rule stays silent.",
        data=s3_state(bucket("opaque-enc", encryption_configured=False, encryption_known=False)),
    ),
    # ------------------------------------------------------ whole-estate ---
    Case(
        case_id="s3-worst-case-bucket",
        service="s3",
        category="multi",
        covers=("S3-001", "S3-002", "S3-003", "S3-004"),
        description="One bucket failing all four rules produces exactly four findings.",
        data=s3_state(
            bucket(
                "everything-wrong",
                public_access_block=None,
                encryption_configured=False,
                bucket_policy=PUBLIC_POLICY,
                acl_grants=[public_acl_grant()],
                policy_is_public=True,
            )
        ),
        expected=(
            Expected("S3-001", "everything-wrong", "MEDIUM"),
            Expected("S3-002", "everything-wrong", "CRITICAL"),
            Expected("S3-003", "everything-wrong", "CRITICAL"),
            Expected("S3-004", "everything-wrong", "MEDIUM"),
        ),
    ),
    Case(
        case_id="s3-multiple-buckets-attribution",
        service="s3",
        category="multi",
        covers=("S3-001", "S3-002", "S3-004"),
        description="Three buckets with different problems are attributed to the right bucket each.",
        data=s3_state(
            bucket("clean-one"),
            bucket("public-one", public_access_block=dict(ALL_PAB_OFF), acl_grants=[public_acl_grant()]),
            bucket("unencrypted-one", encryption_configured=False),
        ),
        expected=(
            Expected("S3-001", "public-one", "MEDIUM"),
            Expected("S3-002", "public-one", "CRITICAL"),
            Expected("S3-004", "unencrypted-one", "MEDIUM"),
        ),
    ),
    Case(
        case_id="s3-no-buckets",
        service="s3",
        category="edge",
        covers=("S3-001", "S3-004"),
        description="An account with no buckets produces no S3 findings.",
        data=s3_state(),
    ),
)
