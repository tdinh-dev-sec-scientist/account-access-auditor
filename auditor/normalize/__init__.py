"""Normalization: raw Boto3 responses -> the internal data model the rules read.

This layer is deliberately separate from the collectors. Collectors decide
*which* API calls to make and how to survive their failures; normalization
decides what the response *means* as data. Because these are pure functions over
plain dictionaries, the exact response shapes AWS returns -- including the
awkward ones, like ``GetBucketLocation`` returning None for us-east-1 -- can be
pinned in tests without a network or a mock client.
"""

from . import cloudtrail, iam, s3

__all__ = ["iam", "s3", "cloudtrail"]
