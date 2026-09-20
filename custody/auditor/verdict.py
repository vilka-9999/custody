"""Rulings on a remediation attempt, and the claims each ruling licenses.

Custody inherits a discipline from its predecessor: a verdict states only what
the evidence supports, and every verdict carries an explicit list of what it
does *not* license anyone to say. The difference between "we checked and found
nothing" and "we could not check" is preserved everywhere, because collapsing
the two is how a failed run comes to look like a clean one.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Dict, List

from custody.auditor.detectors import Detection, DiffContext
from custody.findings import Severity


class Ruling(str, Enum):
    """The four outcomes an attempt can receive."""

    PROVEN = "PROVEN"
    NOT_OBSERVED = "NOT_OBSERVED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    REJECTED = "REJECTED"


PERMITTED: Dict[Ruling, List[str]] = {
    Ruling.PROVEN: [
        "The declared finding is absent from a fresh deterministic survey.",
        "The project's own test suite ran and passed after the change.",
        "Every file written was declared in advance.",
    ],
    Ruling.NOT_OBSERVED: [
        "The attempt ran to completion without violating its contract.",
        "The declared finding was still reported after the change.",
    ],
    Ruling.INSUFFICIENT_EVIDENCE: [
        "The attempt was recorded.",
    ],
    Ruling.REJECTED: [
        "The attempt violated its scope contract or weakened its own gate.",
        "The change was reverted and no code from it survives.",
    ],
}

PROHIBITED: Dict[Ruling, List[str]] = {
    Ruling.PROVEN: [
        "That the code is correct.",
        "That no new defect was introduced.",
        "That the change is the best available fix.",
    ],
    Ruling.NOT_OBSERVED: [
        "That the finding is unfixable.",
        "That the agent acted in bad faith.",
    ],
    Ruling.INSUFFICIENT_EVIDENCE: [
        "That the repository is clean.",
        "That the attempt succeeded.",
        "That the attempt failed.",
    ],
    Ruling.REJECTED: [
        "That the agent intended to deceive.",
    ],
}


@dataclass(frozen=True)
class Judgment:
    """One adjudicated attempt.

    Attributes:
        finding_id: The finding the attempt claimed to address.
        ruling: The outcome.
        reason: One sentence explaining the outcome.
        detections: Deterministic reasons to distrust the attempt.
        evidence: Named facts the ruling rests on.
    """

    finding_id: str
    ruling: Ruling
    reason: str
    detections: List[Detection] = field(default_factory=list)
    evidence: Dict[str, object] = field(default_factory=dict)

    @property
    def permitted_claims(self) -> List[str]:
        """Return what this ruling licenses a reader to say."""
        return list(PERMITTED[self.ruling])

    @property
    def prohibited_claims(self) -> List[str]:
        """Return what this ruling explicitly does not license."""
        return list(PROHIBITED[self.ruling])

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable view for the ledger."""
        return {
            "finding_id": self.finding_id,
            "ruling": self.ruling.value,
            "reason": self.reason,
            "detections": [d.to_dict() for d in self.detections],
            "evidence": dict(self.evidence),
            "permitted_claims": self.permitted_claims,
            "prohibited_claims": self.prohibited_claims,
        }

    def render(self) -> str:
        """Return a human-readable block for the console."""
        lines = ["%s  %s" % (self.finding_id, self.ruling.value), "  %s" % self.reason]
        for detection in self.detections:
            lines.append(
                "  [%s] %s %s" % (detection.severity.value, detection.detector, detection.message)
            )
        lines.append("  Permitted:")
        lines.extend("    - %s" % claim for claim in self.permitted_claims)
        lines.append("  Prohibited:")
        lines.extend("    - %s" % claim for claim in self.prohibited_claims)
        return "\n".join(lines)


def adjudicate(ctx: DiffContext, detections: List[Detection], survey_ran: bool = True) -> Judgment:
    """Rule on one attempt from artifacts alone.

    The order of these checks matters. A contract violation outranks a green
    test suite, because an agent that edited its own gate can make any suite
    green. Missing evidence outranks a clean result, because not looking is
    not the same as looking and finding nothing - and a suite that never ran
    is not a suite that failed, so it yields INSUFFICIENT_EVIDENCE rather than
    a rejection the agent did not earn.
    """
    finding_id = ctx.contract.finding_id
    critical = [d for d in detections if d.severity is Severity.CRITICAL]

    if critical:
        return Judgment(
            finding_id, Ruling.REJECTED,
            "Attempt exceeded its authority or weakened its own verification.",
            detections,
            {"critical_detections": len(critical), "changed_files": sorted(ctx.changed)},
        )

    if not survey_ran:
        return Judgment(
            finding_id, Ruling.INSUFFICIENT_EVIDENCE,
            "The post-change survey could not be completed, so nothing was verified. "
            "This is not a clean result.",
            detections, {"survey_ran": False},
        )

    if not ctx.tests_ran:
        return Judgment(
            finding_id, Ruling.INSUFFICIENT_EVIDENCE,
            "The project's own test suite never ran, so the change was not verified. "
            "This is not a clean result, and it is not a failure either.",
            detections, {"tests_ran": False},
        )

    if not ctx.tests_passed:
        return Judgment(
            finding_id, Ruling.REJECTED,
            "The project's own test suite failed after the change; it was reverted.",
            detections, {"tests_ran": True, "tests_passed": False},
        )

    cleared = not any(f.id == finding_id for f in ctx.findings_after)
    was_present = any(f.id == finding_id for f in ctx.findings_before)

    if not was_present:
        return Judgment(
            finding_id, Ruling.INSUFFICIENT_EVIDENCE,
            "The declared finding was not present before the attempt, so there is "
            "nothing to compare against.",
            detections, {"finding_present_before": False},
        )

    if cleared:
        return Judgment(
            finding_id, Ruling.PROVEN,
            "The finding is gone from a fresh survey, the suite is green, and every "
            "file written was declared.",
            detections,
            {
                "tests_passed": True,
                "finding_cleared": True,
                "changed_files": sorted(ctx.changed),
                "advisory_detections": len(detections),
            },
        )

    return Judgment(
        finding_id, Ruling.NOT_OBSERVED,
        "The attempt stayed inside its contract but the finding is still reported.",
        detections, {"tests_passed": True, "finding_cleared": False},
    )


def summarise(judgments: List[Judgment]) -> Dict[str, int]:
    """Count rulings by kind, including kinds that did not occur."""
    counts = {ruling.value: 0 for ruling in Ruling}
    for judgment in judgments:
        counts[judgment.ruling.value] += 1
    return counts
