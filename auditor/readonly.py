"""Runtime read-only enforcement.

A README promising "this tool is read-only" is a claim. This module makes it a
control: a botocore event hook inspects every API operation the auditor is about
to send and raises unless it appears in the declared inventory
(``auditor.permissions.API_CALLS``).

It is an allowlist, not a verb heuristic, so it also blocks a *read* call the
project never declared -- which is what makes it useful against accidental scope
creep as well as against writes. It fires before the request is signed and sent,
so a blocked call never reaches AWS.

The guard is defence in depth, not the primary control. The primary controls are
that no write call exists in the source (asserted statically by the test suite)
and that the auditor's IAM policy grants no write action.
"""

from __future__ import annotations

import logging
from typing import Any

from .permissions import ALLOWED_OPERATIONS, ReadOnlyViolation

log = logging.getLogger(__name__)

# botocore emits this for every operation, before the request is signed.
_EVENT = "before-call"


class ReadOnlyGuard:
    """Rejects any AWS operation outside the declared read-only inventory."""

    def __init__(self, allowed: frozenset | None = None) -> None:
        self.allowed = allowed if allowed is not None else ALLOWED_OPERATIONS
        self.observed: list[str] = []

    def __call__(self, model: Any = None, **kwargs: Any) -> None:
        if model is None:  # pragma: no cover - botocore always supplies it
            return
        service = getattr(getattr(model, "service_model", None), "service_name", None)
        operation = getattr(model, "name", None)
        if not service or not operation:  # pragma: no cover - defensive
            return

        key = f"{service}:{operation}"
        self.observed.append(key)
        if key not in self.allowed:
            log.error("Blocked AWS operation outside the read-only inventory: %s", key)
            raise ReadOnlyViolation(
                f"Blocked '{key}': the auditor is read-only and only performs the "
                f"operations declared in auditor/permissions.py. If this call is "
                f"legitimate, add it to the inventory (read-only operations only) so "
                f"the generated IAM policy stays in step with the code."
            )

    # -- introspection used by the benchmark and the tests ------------------

    @property
    def call_count(self) -> int:
        return len(self.observed)

    def counts_by_operation(self) -> dict:
        result: dict = {}
        for key in self.observed:
            result[key] = result.get(key, 0) + 1
        return dict(sorted(result.items()))

    def reset(self) -> None:
        self.observed.clear()


def install_read_only_guard(session, guard: ReadOnlyGuard | None = None) -> ReadOnlyGuard:
    """Attach the guard to a boto3 session and return it.

    Registered as a unique handler so installing twice on one session does not
    double-count operations.
    """
    guard = guard or ReadOnlyGuard()
    session.events.register(_EVENT, guard, unique_id="auditor-read-only-guard")
    log.debug("Read-only guard installed (%d operations allowed)", len(guard.allowed))
    return guard


def uninstall_read_only_guard(session) -> None:
    session.events.unregister(_EVENT, unique_id="auditor-read-only-guard")
