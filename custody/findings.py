"""The finding record shared by the surveyor, remediator and auditor.

A finding is the unit of work in Custody. The surveyor opens findings
deterministically, the remediator is granted authority over exactly one at a
time, and the auditor rules on whether the claim to have fixed it holds up.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """How much a finding matters, ordered from worst to least."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        """Return a sort key where 0 is the most severe."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER: List[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
]


class Pillar(str, Enum):
    """Which quality pillar a finding belongs to."""

    SECURITY = "SECURITY"
    DEPENDENCIES = "DEPENDENCIES"
    QUALITY = "QUALITY"


@dataclass(frozen=True)
class Finding:
    """One deterministically detected problem in a repository.

    Attributes:
        id: Stable identifier derived from the rule and location.
        rule: The rule that fired, e.g. ``subprocess-shell-true``.
        pillar: Which pillar the rule scores against.
        severity: How much the finding matters.
        path: Repository-relative file the finding sits in.
        line: One-based line number, or 0 when the finding is file-scoped.
        message: One sentence a human can act on.
        evidence: The source excerpt or data that triggered the rule.
        detail: Rule-specific structured context.
    """

    id: str
    rule: str
    pillar: Pillar
    severity: Severity
    path: str
    line: int
    message: str
    evidence: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable view of the finding."""
        data = asdict(self)
        data["pillar"] = self.pillar.value
        data["severity"] = self.severity.value
        return data

    def location(self) -> str:
        """Return a ``path:line`` reference, or just the path when file-scoped."""
        return f"{self.path}:{self.line}" if self.line else self.path


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Order findings by severity, then location, so runs are reproducible."""
    return sorted(findings, key=lambda f: (f.severity.rank, f.path, f.line, f.rule))


def finding_id(rule: str, path: str, line: int, salt: str = "") -> str:
    """Build a stable, human-readable id for a finding.

    The id must not change between runs for the same underlying problem, so it
    is derived only from the rule and its location, never from run order.
    """
    import hashlib

    raw = f"{rule}|{path}|{line}|{salt}"
    return "CUS-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8].upper()


def group_by_pillar(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """Bucket findings by pillar name, preserving sort order within each."""
    grouped: Dict[str, List[Finding]] = {p.value: [] for p in Pillar}
    for finding in sort_findings(findings):
        grouped[finding.pillar.value].append(finding)
    return grouped


def find_by_id(findings: List[Finding], finding_id_value: str) -> Optional[Finding]:
    """Return the finding with ``finding_id_value``, or ``None``."""
    for finding in findings:
        if finding.id == finding_id_value:
            return finding
    return None
