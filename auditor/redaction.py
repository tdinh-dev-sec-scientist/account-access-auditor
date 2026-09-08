"""Optional redaction of identifiers in a finished report.

A findings report is often the most sensitive artifact a scan produces: it names
principals, buckets, and credential identifiers, and it gets pasted into
tickets, chat, and repositories. Access key IDs are not secrets -- AWS treats
them as public identifiers and they appear in CloudTrail -- but they identify a
specific live credential, so a report destined for anywhere outside the account
should not carry them in full.

Redaction is applied to a rendered report, after detection, so it can never
change what was found: masking is a publishing concern, not a detection one.
The last four characters are kept because that is enough for an operator to
match the finding to a key in the console without publishing the whole ID.
"""

from __future__ import annotations

import copy
import re
from typing import Any

# Long-term (AKIA) and temporary (ASIA) access key identifiers.
ACCESS_KEY_PATTERN = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{12})([0-9A-Z]{4})\b")

# Bare 12-digit AWS account IDs, when the caller asks for those too.
ACCOUNT_ID_PATTERN = re.compile(r"\b(\d{12})\b")

MASK = "…"


def mask_access_keys(text: str) -> str:
    return ACCESS_KEY_PATTERN.sub(lambda m: f"{m.group(1)[:4]}{MASK}{m.group(2)}", text)


def mask_account_ids(text: str) -> str:
    return ACCOUNT_ID_PATTERN.sub(lambda m: f"{m.group(1)[:4]}{MASK}{m.group(1)[-2:]}", text)


def _walk(value: Any, transform) -> Any:
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, dict):
        return {key: _walk(item, transform) for key, item in value.items()}
    if isinstance(value, list):
        return [_walk(item, transform) for item in value]
    return value


def redact_report(
    report: dict[str, Any],
    access_keys: bool = True,
    account_ids: bool = False,
) -> dict[str, Any]:
    """Return a copy of ``report`` with the selected identifiers masked.

    The original is never mutated, so a caller can write a full report locally
    and a redacted one for sharing from the same scan.
    """

    def transform(text: str) -> str:
        if access_keys:
            text = mask_access_keys(text)
        if account_ids:
            text = mask_account_ids(text)
        return text

    redacted = _walk(copy.deepcopy(report), transform)
    redacted.setdefault("metadata", {})["redacted"] = {
        "access_key_ids": access_keys,
        "account_ids": account_ids,
    }
    return redacted
