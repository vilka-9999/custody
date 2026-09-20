"""Tests for the deterministic reward-hacking detectors."""

import unittest
from typing import Dict, List, Optional

from custody.auditor.detectors import (
    DiffContext,
    detect_config_loosened,
    detect_cost_underreport,
    detect_lint_suppressed,
    detect_test_weakened,
    detect_vacuous_fix,
    run_detectors,
)
from custody.findings import Finding, Pillar, Severity
from custody.remediator.contract import ScopeContract

SRC = "pkg/module.py"
TEST = "tests/test_module.py"

SUITE = '''
def test_one():
    """One."""
    assert 1 == 1


def test_two():
    """Two."""
    assert 2 == 2
'''


def context(
    changed: List[str],
    before: Dict[str, str],
    after: Dict[str, Optional[str]],
    paths: Optional[List[str]] = None,
    **kwargs: object,
) -> DiffContext:
    """Build a DiffContext for a single-finding attempt."""
    contract = ScopeContract("CUS-1", paths or [SRC], "hypothesis", "verification", "0" * 40)
    return DiffContext(
        contract=contract,
        changed=changed,
        before=before,
        after={k: v for k, v in after.items() if v is not None},
        **kwargs,
    )


class TestWeakeningTests(unittest.TestCase):
    """Detecting a suite that stopped asking questions."""

    def test_removed_test_is_caught(self) -> None:
        """Deleting a test function is reported."""
        ctx = context([TEST], {TEST: SUITE}, {TEST: SUITE.split("def test_two")[0]})
        names = {d.detector for d in detect_test_weakened(ctx)}
        self.assertIn("test-removed", names)

    def test_deleted_module_is_caught(self) -> None:
        """Deleting a whole test module is reported."""
        ctx = context([TEST], {TEST: SUITE}, {TEST: None})
        names = {d.detector for d in detect_test_weakened(ctx)}
        self.assertIn("test-file-deleted", names)

    def test_vacuous_assertion_is_caught(self) -> None:
        """An assertion that cannot fail is reported."""
        ctx = context([TEST], {TEST: SUITE}, {TEST: SUITE.replace("1 == 1", "True")})
        names = {d.detector for d in detect_test_weakened(ctx)}
        self.assertIn("vacuous-assertion", names)

    def test_new_skip_is_caught(self) -> None:
        """Newly marking a test skip is reported."""
        after = "import pytest\n" + SUITE.replace(
            "def test_one():", "@pytest.mark.skip\ndef test_one():"
        )
        ctx = context([TEST], {TEST: SUITE}, {TEST: after})
        names = {d.detector for d in detect_test_weakened(ctx)}
        self.assertIn("test-skipped", names)

    def test_pre_existing_skip_is_not_reported(self) -> None:
        """A skip that was already there is not a new cheat."""
        skipped = "import pytest\n" + SUITE.replace(
            "def test_one():", "@pytest.mark.skip\ndef test_one():"
        )
        ctx = context([TEST], {TEST: skipped}, {TEST: skipped + "\n# comment\n"})
        names = {d.detector for d in detect_test_weakened(ctx)}
        self.assertNotIn("test-skipped", names)

    def test_added_test_is_not_reported(self) -> None:
        """Adding a real test is not a cheat."""
        after = SUITE + '\n\ndef test_three():\n    """Three."""\n    assert 3 == 3\n'
        ctx = context([TEST], {TEST: SUITE}, {TEST: after})
        names = {d.detector for d in detect_test_weakened(ctx)}
        self.assertEqual(names - {"scope-escape"}, set())

    def test_non_test_file_is_ignored(self) -> None:
        """Source files are not judged by test rules."""
        ctx = context([SRC], {SRC: "def f():\n    pass\n"}, {SRC: "def f():\n    return 1\n"})
        self.assertEqual(detect_test_weakened(ctx), [])


class SuppressionTests(unittest.TestCase):
    """Detecting silenced checkers."""

    def test_new_suppression_is_caught(self) -> None:
        """An added noqa is reported."""
        ctx = context([SRC], {SRC: "import os\n"}, {SRC: "import os  # noqa\n"})
        self.assertTrue(detect_lint_suppressed(ctx))

    def test_unchanged_suppression_is_not_caught(self) -> None:
        """A pre-existing noqa is left alone."""
        text = "import os  # noqa\n"
        ctx = context([SRC], {SRC: text}, {SRC: text + "x = 1\n"})
        self.assertEqual(detect_lint_suppressed(ctx), [])

    def test_removed_suppression_is_not_caught(self) -> None:
        """Removing a suppression is an improvement, not a cheat."""
        ctx = context([SRC], {SRC: "import os  # noqa\n"}, {SRC: "import os\n"})
        self.assertEqual(detect_lint_suppressed(ctx), [])


class GateTests(unittest.TestCase):
    """Detecting quality gates that moved the easy way."""

    def test_lowered_threshold_is_caught(self) -> None:
        """Dropping fail_under is reported."""
        ctx = context(
            ["setup.cfg"],
            {"setup.cfg": "fail_under = 90\n"},
            {"setup.cfg": "fail_under = 10\n"},
        )
        names = {d.detector for d in detect_config_loosened(ctx)}
        self.assertIn("gate-loosened", names)

    def test_raised_threshold_is_not_caught(self) -> None:
        """Tightening a gate is not a cheat."""
        ctx = context(
            ["setup.cfg"],
            {"setup.cfg": "fail_under = 80\n"},
            {"setup.cfg": "fail_under = 95\n"},
        )
        self.assertEqual(detect_config_loosened(ctx), [])

    def test_removed_gate_is_caught(self) -> None:
        """Deleting a threshold entirely is reported."""
        ctx = context(
            ["setup.cfg"],
            {"setup.cfg": "fail_under = 90\n"},
            {"setup.cfg": "[coverage:report]\n"},
        )
        names = {d.detector for d in detect_config_loosened(ctx)}
        self.assertIn("gate-removed", names)


class VacuousFixTests(unittest.TestCase):
    """Detecting a fix that did not fix anything."""

    def _finding(self) -> Finding:
        """Return the finding under test."""
        return Finding("CUS-1", "rule", Pillar.QUALITY, Severity.LOW, SRC, 1, "message")

    def test_unresolved_finding_is_caught(self) -> None:
        """A finding still present after the fix is reported."""
        ctx = context(
            [SRC], {SRC: "a\n"}, {SRC: "b\n"},
            findings_before=[self._finding()], findings_after=[self._finding()],
        )
        self.assertTrue(detect_vacuous_fix(ctx))

    def test_resolved_finding_is_not_caught(self) -> None:
        """A finding that cleared is not reported."""
        ctx = context(
            [SRC], {SRC: "a\n"}, {SRC: "b\n"},
            findings_before=[self._finding()], findings_after=[],
        )
        self.assertEqual(detect_vacuous_fix(ctx), [])


class CostTests(unittest.TestCase):
    """Detecting under-reported spend."""

    def test_underreported_cost_is_caught(self) -> None:
        """Declaring far less than measured is reported."""
        ctx = context([SRC], {SRC: "a\n"}, {SRC: "b\n"},
                      declared_cost_usd=0.001, measured_cost_usd=0.05)
        self.assertTrue(detect_cost_underreport(ctx))

    def test_accurate_cost_is_not_caught(self) -> None:
        """Declaring what was measured is fine."""
        ctx = context([SRC], {SRC: "a\n"}, {SRC: "b\n"},
                      declared_cost_usd=0.05, measured_cost_usd=0.05)
        self.assertEqual(detect_cost_underreport(ctx), [])

    def test_unmeasured_cost_is_not_asserted_on(self) -> None:
        """With no measurement there is no accusation to make."""
        ctx = context([SRC], {SRC: "a\n"}, {SRC: "b\n"},
                      declared_cost_usd=0.0, measured_cost_usd=0.0)
        self.assertEqual(detect_cost_underreport(ctx), [])


class OrderingTests(unittest.TestCase):
    """The detector suite is stable and ordered."""

    def test_results_are_severity_ordered(self) -> None:
        """Critical detections sort ahead of high ones."""
        ctx = context(
            [TEST, SRC],
            {TEST: SUITE, SRC: "import os\n"},
            {TEST: SUITE.split("def test_two")[0], SRC: "import os  # noqa\n"},
        )
        results = run_detectors(ctx)
        ranks = [d.severity.rank for d in results]
        self.assertEqual(ranks, sorted(ranks))

    def test_run_is_deterministic(self) -> None:
        """Three runs over the same context agree exactly."""
        ctx = context([TEST], {TEST: SUITE}, {TEST: SUITE.replace("1 == 1", "True")})
        runs = [[d.detector for d in run_detectors(ctx)] for _ in range(3)]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])


if __name__ == "__main__":
    unittest.main()
