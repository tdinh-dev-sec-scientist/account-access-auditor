"""Offline fixture cases for the six IAM rules."""

from __future__ import annotations

from tests.builders import access_key, iam_group, iam_role, iam_state, iam_user, policy

from . import Case, Expected

# Policy statements reused across cases.
ADMIN = [{"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"}]
ADMIN_STAR_COLON_STAR = [{"Effect": "Allow", "Action": "*:*", "Resource": "*"}]
NOT_ACTION_ADMIN = [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]
NOT_RESOURCE_ADMIN = [{"Effect": "Allow", "Action": "*", "NotResource": "arn:aws:s3:::secret"}]
SERVICE_WIDE = [{"Effect": "Allow", "Action": ["s3:*", "ec2:*"], "Resource": "*"}]
SERVICE_WIDE_SCOPED_RESOURCE = [
    {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::one-bucket/*"}
]
PREFIX_WILDCARD = [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}]
SCOPED = [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}]
DENY_ALL = [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
LOWERCASE_ALLOW = [{"Effect": "allow", "Action": "*", "Resource": "*"}]

CASES = (
    # ------------------------------------------------- IAM-001 / IAM-006 ---
    Case(
        case_id="iam-001-console-no-mfa",
        service="iam",
        category="vulnerable",
        covers=("IAM-001",),
        description="Console login profile with zero MFA devices is HIGH.",
        data=iam_state(users=[iam_user("alice", console_access=True, mfa_devices=0)]),
        expected=(Expected("IAM-001", "user:alice", "HIGH"),),
    ),
    Case(
        case_id="iam-001-console-with-mfa",
        service="iam",
        category="clean",
        covers=("IAM-001",),
        description="Console user with an MFA device produces nothing.",
        data=iam_state(users=[iam_user("alice", console_access=True, mfa_devices=1)]),
    ),
    Case(
        case_id="iam-001-console-multiple-mfa",
        service="iam",
        category="edge",
        covers=("IAM-001",),
        description="Two registered MFA devices still count as protected.",
        data=iam_state(users=[iam_user("alice", console_access=True, mfa_devices=2)]),
    ),
    Case(
        case_id="iam-006-programmatic-no-mfa",
        service="iam",
        category="vulnerable",
        covers=("IAM-006",),
        description="Programmatic-only user without MFA is INFO, never HIGH.",
        data=iam_state(users=[iam_user("svc", console_access=False, mfa_devices=0)]),
        expected=(Expected("IAM-006", "user:svc", "INFO"),),
    ),
    Case(
        case_id="iam-006-programmatic-with-mfa",
        service="iam",
        category="clean",
        covers=("IAM-006",),
        description="Programmatic user that does have MFA produces nothing.",
        data=iam_state(users=[iam_user("svc", console_access=False, mfa_devices=1)]),
    ),
    Case(
        case_id="iam-mfa-unknown-console-state",
        service="iam",
        category="edge",
        covers=("IAM-001", "IAM-006"),
        description="Denied GetLoginProfile leaves console state unknown, so neither MFA rule fires.",
        data=iam_state(users=[iam_user("opaque", console_access=None, mfa_devices=0)]),
    ),
    Case(
        case_id="iam-mfa-unknown-device-count",
        service="iam",
        category="edge",
        covers=("IAM-001", "IAM-006"),
        description="Denied ListMFADevices leaves the device count unknown, so neither MFA rule fires.",
        data=iam_state(users=[iam_user("opaque", console_access=True, mfa_devices=None)]),
    ),
    Case(
        case_id="iam-mfa-no-users-at-all",
        service="iam",
        category="edge",
        covers=("IAM-001", "IAM-006"),
        description="An account with no IAM users produces no IAM findings.",
        data=iam_state(users=[]),
    ),
    # ------------------------------------------------------------ IAM-002 ---
    Case(
        case_id="iam-002-key-under-threshold",
        service="iam",
        category="clean",
        covers=("IAM-002",),
        description="A 30-day-old active key is below the 90-day threshold.",
        data=iam_state(users=[iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=30)])]),
    ),
    Case(
        case_id="iam-002-key-exactly-at-threshold",
        service="iam",
        category="edge",
        covers=("IAM-002",),
        description="A key exactly at 90 days does not fire: the rule is strictly greater-than.",
        data=iam_state(users=[iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=90)])]),
    ),
    Case(
        case_id="iam-002-key-one-day-over",
        service="iam",
        category="edge",
        covers=("IAM-002",),
        description="A key at 91 days is the first age that fires, at MEDIUM.",
        data=iam_state(users=[iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=91)])]),
        expected=(Expected("IAM-002", "user:svc/AKIAEXAMPLE", "MEDIUM"),),
    ),
    Case(
        case_id="iam-002-key-past-escalation",
        service="iam",
        category="severity",
        covers=("IAM-002",),
        description="A key past 180 days escalates from MEDIUM to HIGH.",
        data=iam_state(
            users=[
                iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=400, last_used_days_ago=1)])
            ]
        ),
        expected=(Expected("IAM-002", "user:svc/AKIAEXAMPLE", "HIGH"),),
    ),
    Case(
        case_id="iam-002-key-exactly-at-escalation",
        service="iam",
        category="edge",
        covers=("IAM-002",),
        description="A key exactly at 180 days stays MEDIUM; escalation is strictly greater-than.",
        data=iam_state(users=[iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=180)])]),
        expected=(Expected("IAM-002", "user:svc/AKIAEXAMPLE", "MEDIUM"),),
    ),
    Case(
        case_id="iam-002-unknown-age",
        service="iam",
        category="edge",
        covers=("IAM-002",),
        description="A key with an unknown creation date is not aged-out on a guess.",
        data=iam_state(users=[iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=None)])]),
    ),
    Case(
        case_id="iam-002-inactive-old-key-not-aged",
        service="iam",
        category="edge",
        covers=("IAM-002", "IAM-003"),
        description="An ancient Inactive key is IAM-003 LOW only: rotation does not apply to a disabled key.",
        data=iam_state(
            users=[iam_user("svc", mfa_devices=1, access_keys=[access_key(status="Inactive", age_days=400)])]
        ),
        expected=(Expected("IAM-003", "user:svc/AKIAEXAMPLE", "LOW"),),
    ),
    # ------------------------------------------------------------ IAM-003 ---
    Case(
        case_id="iam-003-inactive-key",
        service="iam",
        category="vulnerable",
        covers=("IAM-003",),
        description="An Inactive key still present is LOW.",
        data=iam_state(users=[iam_user("svc", mfa_devices=1, access_keys=[access_key(status="Inactive")])]),
        expected=(Expected("IAM-003", "user:svc/AKIAEXAMPLE", "LOW"),),
    ),
    Case(
        case_id="iam-003-never-used-old-key",
        service="iam",
        category="vulnerable",
        covers=("IAM-003", "IAM-002"),
        description="An active key never used in 400 days is dormant (MEDIUM) as well as overdue (HIGH).",
        data=iam_state(
            users=[
                iam_user(
                    "svc", mfa_devices=1, access_keys=[access_key(age_days=400, last_used_days_ago=None)]
                )
            ]
        ),
        expected=(
            Expected("IAM-002", "user:svc/AKIAEXAMPLE", "HIGH"),
            Expected("IAM-003", "user:svc/AKIAEXAMPLE", "MEDIUM"),
        ),
    ),
    Case(
        case_id="iam-003-never-used-young-key",
        service="iam",
        category="edge",
        covers=("IAM-003",),
        description="A 10-day-old key that has not been used yet is newly issued, not dormant.",
        data=iam_state(
            users=[
                iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=10, last_used_days_ago=None)])
            ]
        ),
    ),
    Case(
        case_id="iam-003-unused-past-threshold",
        service="iam",
        category="vulnerable",
        covers=("IAM-003",),
        description="An active key last used 90 days ago is past the 45-day dormancy threshold.",
        data=iam_state(
            users=[
                iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=60, last_used_days_ago=90)])
            ]
        ),
        expected=(Expected("IAM-003", "user:svc/AKIAEXAMPLE", "MEDIUM"),),
    ),
    Case(
        case_id="iam-003-unused-exactly-at-threshold",
        service="iam",
        category="edge",
        covers=("IAM-003",),
        description="A key last used exactly 45 days ago fires: the CIS control is 45 days or greater.",
        data=iam_state(
            users=[
                iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=60, last_used_days_ago=45)])
            ]
        ),
        expected=(Expected("IAM-003", "user:svc/AKIAEXAMPLE", "MEDIUM"),),
    ),
    Case(
        case_id="iam-003-recently-used-key",
        service="iam",
        category="clean",
        covers=("IAM-003",),
        description="A key used yesterday is in active service and produces nothing.",
        data=iam_state(
            users=[
                iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=60, last_used_days_ago=1)])
            ]
        ),
    ),
    Case(
        case_id="iam-003-last-used-unknown",
        service="iam",
        category="edge",
        covers=("IAM-003",),
        description="Denied GetAccessKeyLastUsed means dormancy is unknowable, so the rule stays silent.",
        data=iam_state(
            users=[
                iam_user(
                    "svc",
                    mfa_devices=1,
                    access_keys=[access_key(age_days=400, last_used_days_ago=None, last_used_known=False)],
                )
            ]
        ),
        expected=(Expected("IAM-002", "user:svc/AKIAEXAMPLE", "HIGH"),),
    ),
    Case(
        case_id="iam-003-two-keys-one-dormant",
        service="iam",
        category="multi",
        covers=("IAM-002", "IAM-003"),
        description="Two keys on one user are attributed individually by key ID.",
        data=iam_state(
            users=[
                iam_user(
                    "svc",
                    mfa_devices=1,
                    access_keys=[
                        access_key("AKIAACTIVE", age_days=30, last_used_days_ago=1),
                        access_key("AKIADORMANT", age_days=200, last_used_days_ago=None),
                    ],
                )
            ]
        ),
        expected=(
            Expected("IAM-002", "user:svc/AKIADORMANT", "HIGH"),
            Expected("IAM-003", "user:svc/AKIADORMANT", "MEDIUM"),
        ),
    ),
    Case(
        case_id="iam-003-no-keys",
        service="iam",
        category="clean",
        covers=("IAM-002", "IAM-003"),
        description="A user with no access keys produces no key findings.",
        data=iam_state(users=[iam_user("svc", mfa_devices=1, access_keys=[])]),
    ),
    # ------------------------------------------------- IAM-004 / IAM-005 ---
    Case(
        case_id="iam-004-admin-wildcard",
        service="iam",
        category="vulnerable",
        covers=("IAM-004",),
        description='Action "*" on Resource "*" is CRITICAL.',
        data=iam_state(users=[iam_user("dev", mfa_devices=1, policies=[policy("admin", ADMIN)])]),
        expected=(Expected("IAM-004", "user:dev/admin", "CRITICAL"),),
    ),
    Case(
        case_id="iam-004-star-colon-star",
        service="iam",
        category="edge",
        covers=("IAM-004",),
        description='The CIS control\'s literal "*:*" spelling is treated as full admin too.',
        data=iam_state(
            users=[iam_user("dev", mfa_devices=1, policies=[policy("admin", ADMIN_STAR_COLON_STAR)])]
        ),
        expected=(Expected("IAM-004", "user:dev/admin", "CRITICAL"),),
    ),
    Case(
        case_id="iam-004-not-action",
        service="iam",
        category="edge",
        covers=("IAM-004",),
        description='NotAction on Resource "*" grants everything except one service; still CRITICAL.',
        data=iam_state(
            users=[iam_user("dev", mfa_devices=1, policies=[policy("almost-admin", NOT_ACTION_ADMIN)])]
        ),
        expected=(Expected("IAM-004", "user:dev/almost-admin", "CRITICAL"),),
    ),
    Case(
        case_id="iam-004-not-resource",
        service="iam",
        category="edge",
        covers=("IAM-004",),
        description="NotResource is an all-resources grant with a hole in it, so it counts.",
        data=iam_state(
            users=[iam_user("dev", mfa_devices=1, policies=[policy("all-but-one", NOT_RESOURCE_ADMIN)])]
        ),
        expected=(Expected("IAM-004", "user:dev/all-but-one", "CRITICAL"),),
    ),
    Case(
        case_id="iam-004-lowercase-effect",
        service="iam",
        category="edge",
        covers=("IAM-004",),
        description="IAM treats Effect case-insensitively, and so does the analyser.",
        data=iam_state(users=[iam_user("dev", mfa_devices=1, policies=[policy("admin", LOWERCASE_ALLOW)])]),
        expected=(Expected("IAM-004", "user:dev/admin", "CRITICAL"),),
    ),
    Case(
        case_id="iam-004-deny-is-not-a-grant",
        service="iam",
        category="clean",
        covers=("IAM-004",),
        description='Deny "*" on "*" is one of the safest statements possible and must not fire.',
        data=iam_state(users=[iam_user("dev", mfa_devices=1, policies=[policy("guardrail", DENY_ALL)])]),
    ),
    Case(
        case_id="iam-004-supersedes-005",
        service="iam",
        category="edge",
        covers=("IAM-004", "IAM-005"),
        description="A policy with both an admin and a service-wide statement reports IAM-004 only.",
        data=iam_state(
            users=[iam_user("dev", mfa_devices=1, policies=[policy("mixed", ADMIN + SERVICE_WIDE)])]
        ),
        expected=(Expected("IAM-004", "user:dev/mixed", "CRITICAL"),),
    ),
    Case(
        case_id="iam-005-service-wide",
        service="iam",
        category="vulnerable",
        covers=("IAM-005",),
        description='Service-wide wildcards on Resource "*" in a customer policy are HIGH.',
        data=iam_state(users=[iam_user("dev", mfa_devices=1, policies=[policy("broad", SERVICE_WIDE)])]),
        expected=(Expected("IAM-005", "user:dev/broad", "HIGH"),),
    ),
    Case(
        case_id="iam-005-aws-managed-downgraded",
        service="iam",
        category="severity",
        covers=("IAM-005",),
        description="The same shape in an AWS-managed policy is LOW: reviewable, not a misconfiguration.",
        data=iam_state(
            users=[
                iam_user(
                    "dev",
                    mfa_devices=1,
                    policies=[
                        policy("AmazonS3FullAccess", SERVICE_WIDE, policy_type="managed", aws_managed=True)
                    ],
                )
            ]
        ),
        expected=(Expected("IAM-005", "user:dev/AmazonS3FullAccess", "LOW"),),
    ),
    Case(
        case_id="iam-005-service-wide-scoped-resource",
        service="iam",
        category="clean",
        covers=("IAM-005",),
        description="s3:* scoped to one bucket ARN is not an all-resources grant.",
        data=iam_state(
            users=[iam_user("dev", mfa_devices=1, policies=[policy("scoped", SERVICE_WIDE_SCOPED_RESOURCE)])]
        ),
    ),
    Case(
        case_id="iam-005-prefix-wildcard-not-service-wide",
        service="iam",
        category="edge",
        covers=("IAM-005",),
        description='"s3:Get*" is a prefix wildcard, not service-wide, and is out of scope for IAM-005.',
        data=iam_state(users=[iam_user("dev", mfa_devices=1, policies=[policy("readish", PREFIX_WILDCARD)])]),
    ),
    Case(
        case_id="iam-005-scoped-policy-clean",
        service="iam",
        category="clean",
        covers=("IAM-004", "IAM-005"),
        description="A least-privilege policy produces nothing.",
        data=iam_state(users=[iam_user("dev", mfa_devices=1, policies=[policy("least-priv", SCOPED)])]),
    ),
    Case(
        case_id="iam-005-unreadable-policy-document",
        service="iam",
        category="edge",
        covers=("IAM-004", "IAM-005"),
        description="A policy whose document could not be read is a collection gap, not a clean policy.",
        data=iam_state(users=[iam_user("dev", mfa_devices=1, policies=[policy("denied", document=None)])]),
    ),
    Case(
        case_id="iam-005-malformed-policy-document",
        service="iam",
        category="malformed",
        covers=("IAM-004", "IAM-005"),
        description="A policy document that is a string rather than an object degrades to no finding, not a crash.",
        data=iam_state(
            users=[iam_user("dev", mfa_devices=1, policies=[policy("weird", document="not-a-policy")])]
        ),
    ),
    Case(
        case_id="iam-005-statement-not-a-list",
        service="iam",
        category="malformed",
        covers=("IAM-004",),
        description="A single-object Statement (legal IAM) is handled like a one-element list.",
        data=iam_state(
            users=[
                iam_user(
                    "dev",
                    mfa_devices=1,
                    policies=[policy("single", document={"Version": "2012-10-17", "Statement": ADMIN[0]})],
                )
            ]
        ),
        expected=(Expected("IAM-004", "user:dev/single", "CRITICAL"),),
    ),
    Case(
        case_id="iam-005-statement-with-junk-entries",
        service="iam",
        category="malformed",
        covers=("IAM-004",),
        description="Non-object entries inside Statement are skipped without hiding the real one.",
        data=iam_state(
            users=[
                iam_user(
                    "dev",
                    mfa_devices=1,
                    policies=[policy("junky", document={"Statement": ["nonsense", None, ADMIN[0]]})],
                )
            ]
        ),
        expected=(Expected("IAM-004", "user:dev/junky", "CRITICAL"),),
    ),
    Case(
        case_id="iam-005-empty-statement-list",
        service="iam",
        category="edge",
        covers=("IAM-004", "IAM-005"),
        description="A policy with no statements grants nothing.",
        data=iam_state(users=[iam_user("dev", mfa_devices=1, policies=[policy("empty", [])])]),
    ),
    # -------------------------------------------------- group / role scope ---
    Case(
        case_id="iam-group-policy-reported-once",
        service="iam",
        category="multi",
        covers=("IAM-005",),
        description="A broad group policy is reported once at the group, not once per member.",
        data=iam_state(
            users=[
                iam_user("a", mfa_devices=1, group_names=["devs"]),
                iam_user("b", mfa_devices=1, group_names=["devs"]),
            ],
            groups=[iam_group("devs", policies=[policy("broad", SERVICE_WIDE)], members=["a", "b"])],
        ),
        expected=(Expected("IAM-005", "group:devs/broad", "HIGH"),),
    ),
    Case(
        case_id="iam-role-admin-policy",
        service="iam",
        category="vulnerable",
        covers=("IAM-004",),
        description="An admin policy on a role is found, not only on users.",
        data=iam_state(roles=[iam_role("deploy", policies=[policy("admin", ADMIN)])]),
        expected=(Expected("IAM-004", "role:deploy/admin", "CRITICAL"),),
    ),
    Case(
        case_id="iam-all-three-principal-types",
        service="iam",
        category="multi",
        covers=("IAM-004", "IAM-005"),
        description="User, group, and role policies are attributed to the right principal each.",
        data=iam_state(
            users=[iam_user("u", mfa_devices=1, policies=[policy("u-admin", ADMIN)])],
            groups=[iam_group("g", policies=[policy("g-broad", SERVICE_WIDE)])],
            roles=[iam_role("r", policies=[policy("r-broad", SERVICE_WIDE)])],
        ),
        expected=(
            Expected("IAM-004", "user:u/u-admin", "CRITICAL"),
            Expected("IAM-005", "group:g/g-broad", "HIGH"),
            Expected("IAM-005", "role:r/r-broad", "HIGH"),
        ),
    ),
    Case(
        case_id="iam-multiple-users-attribution",
        service="iam",
        category="multi",
        covers=("IAM-001", "IAM-004", "IAM-006"),
        description="Three users with different problems each get their own findings.",
        data=iam_state(
            users=[
                iam_user("console-nomfa", console_access=True, mfa_devices=0),
                iam_user("svc-nomfa", console_access=False, mfa_devices=0),
                iam_user("admin", console_access=True, mfa_devices=1, policies=[policy("root-like", ADMIN)]),
            ]
        ),
        expected=(
            Expected("IAM-001", "user:console-nomfa", "HIGH"),
            Expected("IAM-006", "user:svc-nomfa", "INFO"),
            Expected("IAM-004", "user:admin/root-like", "CRITICAL"),
        ),
    ),
    Case(
        case_id="iam-fully-clean-account",
        service="iam",
        category="clean",
        covers=("IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005", "IAM-006"),
        description="An IAM estate with nothing wrong produces zero findings across all six rules.",
        data=iam_state(
            users=[
                iam_user(
                    "ops",
                    console_access=True,
                    mfa_devices=1,
                    access_keys=[access_key(age_days=10, last_used_days_ago=1)],
                    policies=[policy("scoped", SCOPED)],
                )
            ],
            groups=[iam_group("readers", policies=[policy("scoped", SCOPED)])],
            roles=[iam_role("app", policies=[policy("scoped", SCOPED)])],
        ),
    ),
    Case(
        case_id="iam-empty-state",
        service="iam",
        category="edge",
        covers=("IAM-001", "IAM-004", "IAM-006"),
        description="Completely empty IAM state is handled without error.",
        data={"users": [], "groups": [], "roles": [], "errors": []},
    ),
    Case(
        case_id="iam-missing-optional-keys",
        service="iam",
        category="malformed",
        covers=("IAM-001", "IAM-002"),
        description="A user dict missing optional keys entirely does not raise KeyError.",
        data={"users": [{"username": "sparse", "console_access_enabled": True, "mfa_device_count": 0}]},
        expected=(Expected("IAM-001", "user:sparse", "HIGH"),),
    ),
)
