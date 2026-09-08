"""The standardised finding record.

Every rule emits this same structure, so a consumer -- a reporter, a ticketing
system, a SIEM -- can read any finding without knowing which rule produced it.

Static fields (title, rationale, remediation, compliance) come from the rule
registry; a rule supplies only what varies per resource. That is what keeps the
five-tier model deterministic: ``Finding.build`` refuses a severity the rule did
not declare in its registry entry.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..severity import Severity

# Re-exported for the many modules that import Severity from here.
__all__ = ["Finding", "Severity", "utc_now_iso"]


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass
class Finding:
    """A single observed configuration issue."""

    rule_id: str
    severity: Severity
    service: str
    resource: str
    title: str
    description: str
    remediation: str
    resource_type: str = "unknown"
    rationale: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    compliance: dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(default_factory=utc_now_iso)
    run_id: str | None = None
    status: str = "OPEN"

    # -- construction -------------------------------------------------------

    @classmethod
    def build(
        cls,
        rule_id: str,
        resource: str,
        description: str,
        evidence: dict[str, Any] | None = None,
        severity: Severity | None = None,
        title: str | None = None,
        remediation: str | None = None,
        run_id: str | None = None,
        detected_at: str | None = None,
    ) -> Finding:
        """Create a finding from its registry entry plus the dynamic parts.

        ``severity`` defaults to the rule's declared default and must be one of
        the tiers the rule declared; anything else is a programming error and
        raises rather than silently producing an off-model severity.
        """
        from ..rules.registry import get  # local import: registry imports Severity

        spec = get(rule_id)
        chosen = spec.default_severity if severity is None else Severity(severity)
        if chosen not in spec.severities:
            raise ValueError(
                f"{rule_id} may only emit {[s.value for s in spec.severities]}, not {chosen.value}"
            )

        return cls(
            rule_id=spec.rule_id,
            severity=chosen,
            service=spec.service,
            resource=resource,
            resource_type=spec.resource_type,
            title=title or spec.title,
            description=description,
            rationale=spec.rationale,
            remediation=remediation or spec.remediation,
            evidence=evidence or {},
            compliance=spec.compliance,
            detected_at=detected_at or utc_now_iso(),
            run_id=run_id,
        )

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["fingerprint"] = self.fingerprint
        return data

    @property
    def fingerprint(self) -> str:
        """Stable identity for this finding across runs.

        Deliberately excludes the timestamp and the evidence, so the same issue
        on the same resource keeps the same fingerprint between scans and can be
        de-duplicated by a ticket system.
        """
        payload = json.dumps(
            {"rule_id": self.rule_id, "resource": self.resource, "title": self.title},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    @property
    def sort_key(self):
        return (self.severity.rank, self.service, self.rule_id, self.resource)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"[{self.severity.value}] {self.rule_id} {self.resource}: {self.title}"
