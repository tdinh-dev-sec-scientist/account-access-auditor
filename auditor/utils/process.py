"""Safe environment construction for subprocesses that do not need credentials."""

from __future__ import annotations

import os
import re

_CREDENTIAL_ENV_PATTERN = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|CREDENTIALS?|API_KEY|PRIVATE_KEY|AUTHORIZATION)(?:_|$)",
    re.IGNORECASE,
)
_CREDENTIAL_ENV_EXACT = {
    "CHECKOV_API_KEY",
    "BC_API_KEY",
    "PRISMA_API_KEY",
    "KUBECONFIG",
    "DOCKER_AUTH_CONFIG",
    "GIT_ASKPASS",
    "SSH_AUTH_SOCK",
}


def credential_safe_environment(*, allow: set[str] | None = None) -> dict[str, str]:
    """Remove cloud and credential environment values, with a narrow allowlist."""
    allowed = allow or set()
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AWS_")
        and key not in _CREDENTIAL_ENV_EXACT
        and (key in allowed or not _CREDENTIAL_ENV_PATTERN.search(key))
    }
    # Prevent SDKs from discovering credentials or instance metadata elsewhere.
    environment["AWS_EC2_METADATA_DISABLED"] = "true"
    environment["AWS_CONFIG_FILE"] = os.devnull
    environment["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
    environment["AWS_SDK_LOAD_CONFIG"] = "false"
    for key in allowed:
        if key in os.environ:
            environment[key] = os.environ[key]
    return environment
