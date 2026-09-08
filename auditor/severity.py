"""Centralised five-tier severity model.

Every severity decision in this project resolves to one of these five values.
Rules never invent severity strings: they select a member of this enum, and the
rule registry declares which members each rule is allowed to emit
(``auditor.rules.registry``), which is enforced by the test suite.

NOTE: this is the project's own prioritisation scheme. It is not a CVSS score,
an AWS risk rating, or an industry-standard classification.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

# Lower rank == more urgent. Used for sorting and for --severity / --fail-on.
_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

# Human-facing tier names, used by the ticket reporter.
_LABEL: dict[str, str] = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Informational",
}


class Severity(str, Enum):
    """The five tiers, most urgent first."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    @property
    def label(self) -> str:
        return _LABEL[self.value]

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Parse a severity name case-insensitively.

        Raises ValueError with the valid options rather than a bare KeyError,
        because this parses user input from the CLI and config file.
        """
        if not isinstance(value, str):
            raise ValueError(f"Severity must be a string, got {type(value).__name__}")
        key = value.strip().upper()
        if key not in _RANK:
            raise ValueError(f"Unknown severity '{value}'. Valid values: {', '.join(ordered_names())}")
        return cls(key)

    def at_least(self, other: Severity) -> bool:
        """True if this severity is as urgent as, or more urgent than, ``other``."""
        return self.rank <= other.rank

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


def ordered() -> list[Severity]:
    """All tiers, most urgent first."""
    return sorted(Severity, key=lambda s: s.rank)


def ordered_names() -> list[str]:
    return [s.value for s in ordered()]


def counts(severities: Iterable[Severity]) -> dict[str, int]:
    """Zero-filled histogram, so every tier appears in every report."""
    result = {s.value: 0 for s in ordered()}
    for severity in severities:
        result[Severity(severity).value] += 1
    return result


def most_severe(severities: Iterable[Severity]) -> Severity | None:
    ranked = sorted(severities, key=lambda s: Severity(s).rank)
    return Severity(ranked[0]) if ranked else None
