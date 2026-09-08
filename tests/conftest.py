"""Shared test fixtures.

The AWS environment is neutralised for the whole session: any test that
accidentally reaches for real credentials gets obviously-fake ones and a
predictable region, so a misconfigured developer machine cannot turn a unit test
into a live API call.
"""

from __future__ import annotations

import os

import pytest

FAKE_ENV = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_REGION": "us-east-1",
}


@pytest.fixture(autouse=True, scope="session")
def neutralise_aws_environment():
    saved = {key: os.environ.get(key) for key in list(FAKE_ENV) + ["AWS_PROFILE", "AWS_CA_BUNDLE"]}
    os.environ.update(FAKE_ENV)
    os.environ.pop("AWS_PROFILE", None)
    os.environ.pop("AWS_CA_BUNDLE", None)
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture
def aws(neutralise_aws_environment):
    """An in-process AWS emulation, for tests that exercise the boto3 path."""
    from moto import mock_aws

    with mock_aws():
        yield
