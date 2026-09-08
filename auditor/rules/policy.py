"""Policy-document analysis shared by the IAM and S3 rules.

Pure functions over already-parsed policy documents. Nothing here calls AWS,
and nothing here decides severity -- it reports the *shape* of a policy, and the
rules decide what that shape means.

The deliberate limit: this does not evaluate the AWS authorisation model. It
does not resolve service control policies, permissions boundaries, session
policies, or the interaction between identity and resource policies, so it
reports what a document says rather than what a principal can actually do.
"""

from __future__ import annotations

from typing import Any

# Condition keys that genuinely narrow *who* can call, or *from where*.
# A public Principal constrained by one of these is not open to the internet at
# large; a public Principal constrained only by something else (notably
# aws:SecureTransport, which merely requires HTTPS) still is.
CONSTRAINING_CONDITION_KEYS: set[str] = {
    "aws:sourceip",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalaccount",
    "aws:principalarn",
    "aws:principaltag",
    "aws:sourcearn",
    "aws:sourceaccount",
    "aws:sourceowner",
    "aws:useragent",
    "s3:datalocationaccesspointarn",
}

# Actions that mean "every action". "*:*" is not valid IAM syntax but appears in
# the CIS control text and in hand-written policies, so it is treated the same.
_ADMIN_ACTIONS = {"*", "*:*"}


def as_list(value: Any) -> list[Any]:
    """IAM lets almost every field be a scalar or a list. Normalise to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Statements of a policy document, skipping anything malformed.

    A document that is None, a string, or has a non-object statement yields an
    empty list rather than raising: a malformed policy must degrade one finding,
    not abort the scan.
    """
    if not isinstance(document, dict):
        return []
    return [s for s in as_list(document.get("Statement")) if isinstance(s, dict)]


def _effect(statement: dict[str, Any]) -> str:
    effect = statement.get("Effect")
    return effect.strip().lower() if isinstance(effect, str) else ""


def _strings(value: Any) -> list[str]:
    return [item for item in as_list(value) if isinstance(item, str)]


def applies_to_all_resources(statement: dict[str, Any]) -> bool:
    """True if the statement's resource scope is every resource.

    ``NotResource`` counts: "everything except X" is an all-resources grant with
    a hole in it, and the CIS control's concern -- unbounded blast radius --
    applies to it just as much.
    """
    if statement.get("NotResource") is not None:
        return True
    return "*" in _strings(statement.get("Resource"))


def condition_keys(statement: dict[str, Any]) -> list[str]:
    """Every condition key referenced by the statement, lowercased."""
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return []
    keys: list[str] = []
    for operands in condition.values():
        if isinstance(operands, dict):
            keys.extend(str(key).lower() for key in operands)
    return sorted(set(keys))


def constraining_condition_keys(statement: dict[str, Any]) -> list[str]:
    """The subset of condition keys that actually narrows who may call."""
    return [key for key in condition_keys(statement) if key in CONSTRAINING_CONDITION_KEYS]


def analyze_permissions(document: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    """Classify Allow statements whose resource scope is every resource.

    Returns two buckets:
      ``admin_wildcard``   -- Action "*" (or NotAction, which is "everything
                              except") on all resources: the CIS 1.16 condition.
      ``service_wildcard`` -- service-wide actions such as "s3:*" on all
                              resources.

    Deny statements are ignored: a Deny is not a grant, and reporting
    ``Deny "*" on "*"`` as an over-permission would be a false positive on one
    of the safest statements a policy can contain.
    """
    result: dict[str, list[dict[str, Any]]] = {"admin_wildcard": [], "service_wildcard": []}

    for statement in statements(document):
        if _effect(statement) != "allow":
            continue
        if not applies_to_all_resources(statement):
            continue

        actions = _strings(statement.get("Action"))
        not_action = _strings(statement.get("NotAction"))

        entry = {
            "sid": statement.get("Sid"),
            "actions": actions or [f"NotAction:{item}" for item in not_action],
            "resource_scope": "NotResource" if statement.get("NotResource") is not None else "*",
            "has_condition": bool(statement.get("Condition")),
            "condition_keys": condition_keys(statement),
        }

        if any(action in _ADMIN_ACTIONS for action in actions) or not_action:
            result["admin_wildcard"].append(entry)
            continue

        service_wildcards = sorted({a for a in actions if a.endswith(":*")})
        if service_wildcards:
            result["service_wildcard"].append({**entry, "actions": service_wildcards})

    return result


def _principal_is_public(statement: dict[str, Any]) -> bool:
    """True if the statement's principal is the anonymous wildcard.

    ``NotPrincipal`` with Allow counts: "everyone except X" includes anonymous
    callers.
    """
    if statement.get("NotPrincipal") is not None:
        return True

    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        # Only the AWS key can name the anonymous principal. Service, Federated
        # and CanonicalUser principals are named identities, not the public.
        return "*" in _strings(principal.get("AWS"))
    return False


def public_principal_statements(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Allow statements granting access to an anonymous principal."""
    matches: list[dict[str, Any]] = []

    for statement in statements(document):
        if _effect(statement) != "allow":
            continue
        if not _principal_is_public(statement):
            continue

        constraining = constraining_condition_keys(statement)
        matches.append(
            {
                "sid": statement.get("Sid"),
                "actions": _strings(statement.get("Action")),
                "resources": _strings(statement.get("Resource")),
                "principal_form": "NotPrincipal" if statement.get("NotPrincipal") is not None else "*",
                "has_condition": bool(statement.get("Condition")),
                "condition_keys": condition_keys(statement),
                # The distinction that matters: a condition that narrows *who*
                # can call, versus one (aws:SecureTransport) that does not.
                "constraining_condition_keys": constraining,
                "is_effectively_constrained": bool(constraining),
            }
        )

    return matches
