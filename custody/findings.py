"""The finding record shared by the surveyor, remediator and auditor.

A finding is the unit of work in Custody. The surveyor opens findings
deterministically, the remediator is granted authority over exactly one at a
time, and the auditor rules on whether the claim to have fixed it holds up.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


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


_SEVERITY_ORDER: list[Severity] = [
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
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the finding."""
        data = asdict(self)
        data["pillar"] = self.pillar.value
        data["severity"] = self.severity.value
        return data

    def location(self) -> str:
        """Return a ``path:line`` reference, or just the path when file-scoped."""
        return f"{self.path}:{self.line}" if self.line else self.path


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings by severity, then location, so runs are reproducible."""
    return sorted(findings, key=lambda f: (f.severity.rank, f.path, f.line, f.rule))


def finding_id(rule: str, path: str, anchor: str, ordinal: int = 0) -> str:
    """Build a stable, human-readable id for a finding.

    The id is derived from the rule, the file, and the *content* of the
    offending line - never from its line number. An earlier version hashed
    the line number, which meant inserting one blank line above a finding
    changed its id: the contracted id vanished from a fresh survey and an
    unfixed finding adjudicated as PROVEN. An id must survive the code
    around it moving; only a change to the flagged content itself may
    retire it.

    ``ordinal`` disambiguates identical content appearing more than once in
    the same file, counted in line order.
    """
    import hashlib

    raw = f"{rule}|{path}|{anchor}|{ordinal}"
    return "CUS-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8].upper()


def anchor_ids(findings: list[Finding]) -> list[Finding]:
    """Re-derive every finding's id from its content anchor.

    The anchor is the finding's evidence (the stripped source line); findings
    with no evidence fall back to their line number, which is the best
    identity available for them. Duplicate anchors within one file take
    ordinals in line order, so two identical dangerous calls get distinct,
    stable ids.
    """
    from dataclasses import replace

    counts: dict[tuple[str, str, str], int] = {}
    anchored: list[Finding] = []
    for finding in sorted(findings, key=lambda f: (f.path, f.line, f.rule)):
        anchor = finding.evidence.strip() or f"@{finding.line}"
        key = (finding.rule, finding.path, anchor)
        ordinal = counts.get(key, 0)
        counts[key] = ordinal + 1
        new_id = finding_id(finding.rule, finding.path, anchor, ordinal)
        anchored.append(replace(finding, id=new_id))
    return anchored


def instance_count(findings: list[Finding], rule: str, path: str) -> int:
    """Count findings of ``rule`` in ``path``.

    Ids retire when the flagged line's content changes, which a cosmetic
    edit can cause without fixing anything. The instance count cannot be
    moved that way: it drops only when the rule genuinely stops firing on
    an occurrence, so adjudication requires both signals before calling a
    finding cleared.
    """
    return sum(1 for f in findings if f.rule == rule and f.path == path)


def group_by_pillar(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Bucket findings by pillar name, preserving sort order within each."""
    grouped: dict[str, list[Finding]] = {p.value: [] for p in Pillar}
    for finding in sort_findings(findings):
        grouped[finding.pillar.value].append(finding)
    return grouped


def find_by_id(findings: list[Finding], finding_id_value: str) -> Finding | None:
    """Return the finding with ``finding_id_value``, or ``None``."""
    for finding in findings:
        if finding.id == finding_id_value:
            return finding
    return None
