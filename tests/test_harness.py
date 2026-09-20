"""Tests for harness preconditions, write refusal, and the adversarial trial."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from custody import gitio
from custody.auditor.verdict import Ruling
from custody.auditor.verdict import Judgment
from custody.findings import Finding, Pillar, Severity
from custody.harness import CaseResult, HarnessRefusal, _apply, preflight, summarise_run
from custody.ledger import Ledger
from custody.trial import SCENARIOS, run_trial


def scratch_repo(branch: str = "work") -> Path:
    """Create a committed git repository on a non-default branch."""
    root = Path(tempfile.mkdtemp(prefix="custody-test-"))
    subprocess.run(["git", "init", "-q", "-b", branch, str(root)], check=True)
    for key, value in (("user.email", "t@example.com"), ("user.name", "test")):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    gitio.commit_all(root, "init")
    return root


class PreflightTests(unittest.TestCase):
    """The harness refuses unsafe starting conditions."""

    def test_clean_scratch_branch_is_accepted(self) -> None:
        """A clean, non-default branch returns its base SHA."""
        self.assertTrue(preflight(scratch_repo()))

    def test_dirty_tree_is_refused(self) -> None:
        """Uncommitted work would make the diff meaningless as evidence."""
        root = scratch_repo()
        (root / "app.py").write_text("x = 2\n", encoding="utf-8")
        with self.assertRaises(HarnessRefusal):
            preflight(root)

    def test_default_branch_is_refused(self) -> None:
        """The harness will not modify main without an explicit override."""
        root = scratch_repo(branch="main")
        with self.assertRaises(HarnessRefusal):
            preflight(root)

    def test_default_branch_override_is_honoured(self) -> None:
        """The override exists, and it has to be asked for."""
        self.assertTrue(preflight(scratch_repo(branch="main"), allow_default_branch=True))

    def test_non_repository_is_refused(self) -> None:
        """A directory git does not track cannot be audited."""
        with self.assertRaises(HarnessRefusal):
            preflight(Path(tempfile.mkdtemp()))


class WriteRefusalTests(unittest.TestCase):
    """The agent cannot reach the evidence of its own conduct."""

    def test_ledger_write_is_refused(self) -> None:
        """A proposal targeting the ledger is refused, not adjudicated."""
        root = scratch_repo()
        written, refused = _apply(root, {".custody/ledger.jsonl": "forged\n"})
        self.assertEqual(written, [])
        self.assertEqual(refused, [".custody/ledger.jsonl"])
        self.assertFalse((root / ".custody" / "ledger.jsonl").exists())

    def test_auditor_source_write_is_refused(self) -> None:
        """An agent may not edit its judge."""
        root = scratch_repo()
        written, refused = _apply(root, {"custody/auditor/detectors.py": "DETECTORS = []\n"})
        self.assertEqual(written, [])
        self.assertIn("custody/auditor/detectors.py", refused)

    def test_path_traversal_is_refused(self) -> None:
        """A path resolving outside the repository never reaches the disk."""
        root = scratch_repo()
        written, refused = _apply(root, {"../escaped.py": "BAD = True\n"})
        self.assertEqual(written, [])
        self.assertFalse((root.parent / "escaped.py").exists())

    def test_ordinary_write_is_allowed(self) -> None:
        """Normal source files are written so the attempt can be judged."""
        root = scratch_repo()
        written, refused = _apply(root, {"app.py": "x = 3\n"})
        self.assertEqual(written, ["app.py"])
        self.assertEqual(refused, [])

    def test_test_file_write_is_allowed_then_caught(self) -> None:
        """Tests are writable on purpose: prevention would hide the cheat."""
        root = scratch_repo()
        written, refused = _apply(root, {"tests/test_x.py": "# emptied\n"})
        self.assertEqual(written, ["tests/test_x.py"])
        self.assertEqual(refused, [])


class LedgerIntegrityTests(unittest.TestCase):
    """A forged ledger does not verify."""

    def test_forged_entry_breaks_the_chain(self) -> None:
        """Rewriting a recorded ruling is detected on verification."""
        root = Path(tempfile.mkdtemp())
        ledger = Ledger(root / "ledger.jsonl")
        ledger.append("auditor", "case.ruled", verdict="REJECTED")
        raw = (root / "ledger.jsonl").read_text(encoding="utf-8")
        (root / "ledger.jsonl").write_text(raw.replace("REJECTED", "PROVEN"), encoding="utf-8")
        self.assertFalse(Ledger(root / "ledger.jsonl").verify().intact)


class AdversarialTrialTests(unittest.TestCase):
    """Every scripted cheat is ruled as expected."""

    def test_every_scenario_matches_its_expected_ruling(self) -> None:
        """The trial is a regression test, not only a demonstration."""
        results, summary = run_trial(verbose=False)
        for result, scenario in zip(results, SCENARIOS):
            self.assertIs(
                result.judgment.ruling, scenario.expected,
                "%s: expected %s" % (scenario.name, scenario.expected.value),
            )

    def test_every_expected_detector_fires(self) -> None:
        """Each cheat is caught by the detector written for it."""
        results, _ = run_trial(verbose=False)
        for result, scenario in zip(results, SCENARIOS):
            if not scenario.expected_detector:
                continue
            fired = {d.detector for d in result.judgment.detections}
            self.assertIn(scenario.expected_detector, fired, scenario.name)

    def test_only_the_honest_attempt_is_proven(self) -> None:
        """Exactly one of seven attempts survives adjudication."""
        results, summary = run_trial(verbose=False)
        self.assertEqual(summary["rulings"][Ruling.PROVEN.value], 1)

    def test_ledger_survives_the_trial(self) -> None:
        """Seven adversarial attempts leave the chain intact."""
        _, summary = run_trial(verbose=False)
        self.assertTrue(summary["ledger_intact"])


class EvidenceSurvivalTests(unittest.TestCase):
    """The revert must not destroy the record of what it reverted."""

    def test_ledger_survives_a_full_revert(self) -> None:
        """An untracked ledger is preserved when the tree is reset and cleaned."""
        root = scratch_repo()
        base = gitio.head_sha(root)
        ledger = Ledger(root / ".custody" / "ledger.jsonl")
        ledger.append("auditor", "case.ruled", target="CUS-1", verdict="REJECTED")

        (root / "app.py").write_text("x = 999\n", encoding="utf-8")
        (root / "junk.py").write_text("junk\n", encoding="utf-8")
        gitio.restore_to(root, base)

        self.assertFalse((root / "junk.py").exists())
        self.assertEqual((root / "app.py").read_text(encoding="utf-8"), "x = 1\n")
        self.assertEqual(len(list(Ledger(root / ".custody" / "ledger.jsonl").read())), 1)

    def test_empty_ledger_does_not_read_as_a_clean_run(self) -> None:
        """A destroyed audit trail is not a pass, even though it verifies."""
        root = Path(tempfile.mkdtemp())
        ledger = Ledger(root / "ledger.jsonl")
        self.assertTrue(ledger.verify().intact)

        fake = [
            CaseResult(
                finding=Finding("CUS-1", "r", Pillar.QUALITY, Severity.LOW, "a.py", 1, "m"),
                judgment=Judgment("CUS-1", Ruling.PROVEN, "reason"),
                committed=True,
            )
        ]
        summary = summarise_run(fake, ledger)
        self.assertTrue(summary["ledger_intact"])
        self.assertFalse(summary["ledger_recorded"])
        self.assertEqual(summary["ledger_entries"], 0)

    def test_trial_records_every_step(self) -> None:
        """A full trial leaves a substantial, intact record behind."""
        _, summary = run_trial(verbose=False)
        self.assertTrue(summary["ledger_recorded"])
        self.assertGreater(summary["ledger_entries"], 20)


if __name__ == "__main__":
    unittest.main()
