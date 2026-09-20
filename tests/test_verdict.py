"""Tests for adjudication and the claims each ruling licenses."""

import unittest

from custody.auditor.detectors import Detection, DiffContext
from custody.auditor.verdict import Ruling, adjudicate, summarise
from custody.findings import Finding, Pillar, Severity
from custody.remediator.contract import ScopeContract

SRC = "pkg/module.py"


def finding(finding_id: str = "CUS-1") -> Finding:
    """Return a finding of the rule under adjudication."""
    return Finding(finding_id, "rule", Pillar.QUALITY, Severity.LOW, SRC, 1, "message")


def context(**kwargs: object) -> DiffContext:
    """Build a DiffContext describing an honest attempt with a green suite.

    ``tests_ran`` is set explicitly because DiffContext defaults are
    pessimistic: unstated evidence counts as absent.
    """
    defaults = {
        "contract": ScopeContract("CUS-1", [SRC], "hypothesis", "verification", "0" * 40),
        "changed": [SRC],
        "before": {SRC: "a\n"},
        "after": {SRC: "b\n"},
        "findings_before": [finding()],
        "findings_after": [],
        "tests_ran": True,
        "tests_passed": True,
        "cost_measurable": True,
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

    def test_reworded_finding_is_not_proven(self) -> None:
        """A retired id alone does not clear a finding the rule still reports.

        Editing the flagged line cosmetically changes its content anchor, so
        the contracted id vanishes from a fresh survey - but the rule fires
        exactly as often as before. Both signals must clear for PROVEN.
        """
        ctx = context(findings_after=[finding("CUS-2")])
        self.assertIs(adjudicate(ctx, []).ruling, Ruling.NOT_OBSERVED)

    def test_fixing_one_of_two_instances_is_proven(self) -> None:
        """A genuine fix is not penalised for a sibling finding surviving."""
        ctx = context(
            findings_before=[finding("CUS-1"), finding("CUS-2")],
            findings_after=[finding("CUS-2")],
        )
        self.assertIs(adjudicate(ctx, []).ruling, Ruling.PROVEN)


class ClaimBoundaryTests(unittest.TestCase):
    """Every ruling states what it does not license."""

    def test_proven_does_not_license_correctness(self) -> None:
        """PROVEN explicitly refuses the correctness claim."""
        judgment = adjudicate(context(), [])
        prohibited = " ".join(judgment.prohibited_claims).lower()
        self.assertIn("correct", prohibited)

    def test_every_ruling_has_both_lists(self) -> None:
        """No ruling is issued without stated boundaries."""
        cases: list[DiffContext] = [context(), context(findings_after=[finding()])]
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


class UnrunSuiteTests(unittest.TestCase):
    """A suite that never ran is not a suite that failed."""

    def test_absent_suite_is_insufficient_not_rejected(self) -> None:
        """A repository with no tests does not earn a rejection."""
        judgment = adjudicate(context(tests_ran=False, tests_passed=False), [])
        self.assertIs(judgment.ruling, Ruling.INSUFFICIENT_EVIDENCE)
        self.assertIn("never ran", judgment.reason)

    def test_absent_suite_claims_neither_outcome(self) -> None:
        """Neither success nor failure may be read from a missing suite."""
        judgment = adjudicate(context(tests_ran=False, tests_passed=False), [])
        prohibited = " ".join(judgment.prohibited_claims).lower()
        self.assertIn("succeeded", prohibited)
        self.assertIn("failed", prohibited)

    def test_failed_suite_is_still_rejected(self) -> None:
        """A suite that ran and failed is a rejection, as before."""
        judgment = adjudicate(context(tests_ran=True, tests_passed=False), [])
        self.assertIs(judgment.ruling, Ruling.REJECTED)

    def test_cheating_still_outranks_a_missing_suite(self) -> None:
        """A contract violation is decided before evidence is weighed."""
        cheat = Detection("scope-escape", Severity.CRITICAL, SRC, "wrote an undeclared file")
        judgment = adjudicate(context(tests_ran=False, tests_passed=False), [cheat])
        self.assertIs(judgment.ruling, Ruling.REJECTED)


# This block sits after every test class on purpose: an earlier version
# placed it mid-file, and direct invocation silently never defined the
# classes below it - a check that stopped running while reporting clean.
if __name__ == "__main__":
    unittest.main()
