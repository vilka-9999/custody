"""Tests for adjudication and the claims each ruling licenses."""

import unittest
from typing import List

from custody.auditor.detectors import Detection, DiffContext
from custody.auditor.verdict import Ruling, adjudicate, summarise
from custody.findings import Finding, Pillar, Severity
from custody.remediator.contract import ScopeContract

SRC = "pkg/module.py"


def finding() -> Finding:
    """Return the finding under adjudication."""
    return Finding("CUS-1", "rule", Pillar.QUALITY, Severity.LOW, SRC, 1, "message")


def context(**kwargs: object) -> DiffContext:
    """Build a DiffContext with sensible defaults."""
    defaults = {
        "contract": ScopeContract("CUS-1", [SRC], "hypothesis", "verification", "0" * 40),
        "changed": [SRC],
        "before": {SRC: "a\n"},
        "after": {SRC: "b\n"},
        "findings_before": [finding()],
        "findings_after": [],
        "tests_passed": True,
    }
    defaults.update(kwargs)
    return DiffContext(**defaults)


class AdjudicationTests(unittest.TestCase):
    """Ordering of the checks that produce a ruling."""

    def test_clean_fix_is_proven(self) -> None:
        """A cleared finding with a green suite is PROVEN."""
        self.assertIs(adjudicate(context(), []).ruling, Ruling.PROVEN)

    def test_unresolved_finding_is_not_observed(self) -> None:
        """A contract-abiding attempt that did not fix it is NOT_OBSERVED."""
        ctx = context(findings_after=[finding()])
        self.assertIs(adjudicate(ctx, []).ruling, Ruling.NOT_OBSERVED)

    def test_critical_detection_outranks_a_green_suite(self) -> None:
        """A cheat is rejected even when every test passes."""
        cheat = Detection("test-removed", Severity.CRITICAL, SRC, "removed a test")
        self.assertIs(adjudicate(context(), [cheat]).ruling, Ruling.REJECTED)

    def test_red_suite_is_rejected(self) -> None:
        """A failing suite means the change does not survive."""
        self.assertIs(adjudicate(context(tests_passed=False), []).ruling, Ruling.REJECTED)

    def test_missing_survey_is_insufficient_not_clean(self) -> None:
        """Not looking is never reported as having looked and found nothing."""
        judgment = adjudicate(context(), [], survey_ran=False)
        self.assertIs(judgment.ruling, Ruling.INSUFFICIENT_EVIDENCE)
        self.assertIn("not a clean result", judgment.reason)

    def test_absent_baseline_is_insufficient(self) -> None:
        """With nothing to compare against, nothing is concluded."""
        ctx = context(findings_before=[])
        self.assertIs(adjudicate(ctx, []).ruling, Ruling.INSUFFICIENT_EVIDENCE)


class ClaimBoundaryTests(unittest.TestCase):
    """Every ruling states what it does not license."""

    def test_proven_does_not_license_correctness(self) -> None:
        """PROVEN explicitly refuses the correctness claim."""
        judgment = adjudicate(context(), [])
        prohibited = " ".join(judgment.prohibited_claims).lower()
        self.assertIn("correct", prohibited)

    def test_every_ruling_has_both_lists(self) -> None:
        """No ruling is issued without stated boundaries."""
        cases: List[DiffContext] = [context(), context(findings_after=[finding()])]
        for ctx in cases:
            judgment = adjudicate(ctx, [])
            self.assertTrue(judgment.permitted_claims)
            self.assertTrue(judgment.prohibited_claims)

    def test_summary_counts_rulings_that_did_not_occur(self) -> None:
        """A ruling with zero instances still appears, so zero is visible."""
        counts = summarise([adjudicate(context(), [])])
        self.assertEqual(counts[Ruling.PROVEN.value], 1)
        self.assertIn(Ruling.INSUFFICIENT_EVIDENCE.value, counts)
        self.assertEqual(counts[Ruling.REJECTED.value], 0)


if __name__ == "__main__":
    unittest.main()
