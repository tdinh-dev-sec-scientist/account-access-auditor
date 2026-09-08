"""Collection: the only part of the auditor that talks to AWS.

Each collector returns normalized state plus an ``errors`` list. Collectors make
no security judgement; the rules make no API calls. That separation is what
allows the entire detection path to be tested offline.
"""

from . import cloudtrail, iam, s3

COLLECTORS = {
    "iam": iam.collect,
    "s3": s3.collect,
    "cloudtrail": cloudtrail.collect,
}

REQUIRED_PERMISSIONS = {
    "iam": iam.REQUIRED_PERMISSIONS,
    "s3": s3.REQUIRED_PERMISSIONS,
    "cloudtrail": cloudtrail.REQUIRED_PERMISSIONS,
}

__all__ = ["COLLECTORS", "REQUIRED_PERMISSIONS", "iam", "s3", "cloudtrail"]
