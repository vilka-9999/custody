"""Tests for the test runner, which never reports an absent suite as a pass."""

import sys
import tempfile
import unittest
from pathlib import Path

from custody.testing import TestOutcome, detect_command, run_tests

PASSING_SUITE = '''"""Suite."""

import unittest


class T(unittest.TestCase):
    """T."""

    def test_passes(self) -> None:
        """Passes."""
        self.assertTrue(True)
'''

FAILING_SUITE = '''"""Suite."""

import unittest


class T(unittest.TestCase):
    """T."""

    def test_fails(self) -> None:
        """Fails."""
        self.assertEqual(1, 2)
'''


def repo_with(suite: str) -> Path:
    """Create a repository containing ``suite`` under tests/."""
    root = Path(tempfile.mkdtemp())
    (root / "tests").mkdir()
    (root / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (root / "tests" / "test_s.py").write_text(suite, encoding="utf-8")
    return root


class DetectionTests(unittest.TestCase):
    """Choosing how to run a project's tests."""

    def test_unittest_is_the_dependency_free_fallback(self) -> None:
        """A tests/ directory is runnable with the standard library alone."""
        command = detect_command(repo_with(PASSING_SUITE))
        self.assertIsNotNone(command)
        self.assertIn("unittest", command or [])
        self.assertEqual((command or [])[0], sys.executable)

    def test_repository_without_tests_yields_no_command(self) -> None:
        """There is nothing to run, and that is said plainly."""
        self.assertIsNone(detect_command(Path(tempfile.mkdtemp())))


class OutcomeTests(unittest.TestCase):
    """The three outcomes are kept distinct."""

    def test_passing_suite_reports_a_pass(self) -> None:
        """A green suite is ran and passed."""
        outcome = run_tests(repo_with(PASSING_SUITE))
        self.assertTrue(outcome.ran)
        self.assertTrue(outcome.passed)
        self.assertEqual(outcome.returncode, 0)

    def test_failing_suite_reports_a_failure(self) -> None:
        """A red suite is ran and did not pass."""
        outcome = run_tests(repo_with(FAILING_SUITE))
        self.assertTrue(outcome.ran)
        self.assertFalse(outcome.passed)
        self.assertNotEqual(outcome.returncode, 0)
        self.assertIn("FAILED", outcome.output)

    def test_absent_suite_is_neither_pass_nor_failure(self) -> None:
        """A missing suite did not run, and must not read as a pass."""
        outcome = run_tests(Path(tempfile.mkdtemp()))
        self.assertFalse(outcome.ran)
        self.assertFalse(outcome.passed)
        self.assertIn("not a pass", outcome.summary())

    def test_missing_runner_is_reported_as_not_run(self) -> None:
        """An uninstalled runner is a gap in evidence, not a test failure."""
        outcome = run_tests(repo_with(PASSING_SUITE), command=["definitely-not-a-runner"])
        self.assertFalse(outcome.ran)
        self.assertFalse(outcome.passed)
        self.assertIn("not installed", outcome.reason)

    def test_timeout_is_reported_as_not_run(self) -> None:
        """A suite killed for running too long proved nothing."""
        root = repo_with(PASSING_SUITE)
        outcome = run_tests(
            root, command=[sys.executable, "-c", "import time; time.sleep(30)"], timeout=1
        )
        self.assertFalse(outcome.ran)
        self.assertIn("exceeded", outcome.reason)

    def test_summary_never_claims_a_pass_it_did_not_see(self) -> None:
        """Every not-run summary says so explicitly."""
        for outcome in (
            TestOutcome(ran=False, passed=False, command=[], reason="no suite"),
            TestOutcome(ran=False, passed=False, command=["x"], reason="timed out"),
        ):
            self.assertIn("not a pass", outcome.summary())

    def test_output_is_captured_and_bounded(self) -> None:
        """The transcript is kept for diagnosis but cannot grow without limit."""
        outcome = run_tests(repo_with(FAILING_SUITE))
        self.assertTrue(outcome.output)
        self.assertLessEqual(len(outcome.output), 20000)

    def test_ledger_view_carries_the_distinction(self) -> None:
        """The recorded form keeps ran and passed separate."""
        recorded = run_tests(Path(tempfile.mkdtemp())).to_dict()
        self.assertIn("ran", recorded)
        self.assertIn("passed", recorded)
        self.assertFalse(recorded["ran"])


if __name__ == "__main__":
    unittest.main()
