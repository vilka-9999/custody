"""Regressions for vulnerabilities found in review.

Each test here corresponds to a confirmed bypass. They are kept together so
that the class of attack stays visible: in every case a guard existed and
looked correct, but was applied to the wrong representation of the input.
"""

import json
import tempfile
import unittest
from pathlib import Path

from custody.auditor.detectors import DiffContext, detect_cost_underreport
from custody.harness import _apply
from custody.ledger import Ledger, LedgerError, canonical_json, digest
from custody.remediator.contract import (
    ScopeContract,
    is_integrity_critical,
    is_protected,
    is_repo_relative,
)
from custody.surveyor.ast_rules import survey_source


def repo_with_protected_files() -> Path:
    """Create a tree containing the paths an agent must never write."""
    root = Path(tempfile.mkdtemp())
    (root / "custody" / "auditor").mkdir(parents=True)
    (root / "custody" / "ledger.py").write_text("REAL = True\n", encoding="utf-8")
    (root / "custody" / "auditor" / "detectors.py").write_text(
        "DETECTORS = ['real']\n", encoding="utf-8"
    )
    (root / ".custody").mkdir()
    (root / ".custody" / "ledger.jsonl").write_text("{}\n", encoding="utf-8")
    (root / "sub").mkdir()
    return root


class TraversalBypassTests(unittest.TestCase):
    """A path that cancels back onto protected territory must be refused.

    The guard checked the raw proposal key against a glob. ``a/../custody/
    ledger.py`` is not textually equal to any protected glob, and it resolves
    *inside* the repository, so it passed both the protection check and the
    containment check while landing exactly on the ledger.
    """

    def setUp(self) -> None:
        """Create a repository with protected files present."""
        self.root = repo_with_protected_files()

    def _attempt(self, key: str) -> tuple:
        """Try to write through ``key`` and return written and refused lists."""
        return _apply(self.root, {key: "FORGED = True\n"})

    def test_dotdot_onto_the_ledger_module_is_refused(self) -> None:
        """The canonical target is what decides, not the spelling."""
        written, refused = self._attempt("sub/../custody/ledger.py")
        self.assertEqual(written, [])
        self.assertTrue(refused)
        self.assertEqual(
            (self.root / "custody" / "ledger.py").read_text(encoding="utf-8"),
            "REAL = True\n",
        )

    def test_dotdot_onto_the_auditor_is_refused(self) -> None:
        """An agent may not reach its judge by another spelling."""
        written, _ = self._attempt("sub/../custody/auditor/detectors.py")
        self.assertEqual(written, [])
        self.assertIn("real", (self.root / "custody" / "auditor" / "detectors.py").read_text())

    def test_dotdot_onto_the_ledger_file_is_refused(self) -> None:
        """The recorded proceedings stay out of reach."""
        written, _ = self._attempt("sub/../.custody/ledger.jsonl")
        self.assertEqual(written, [])
        self.assertEqual((self.root / ".custody" / "ledger.jsonl").read_text(), "{}\n")

    def test_redundant_segments_are_refused(self) -> None:
        """Noise in the path does not change where it lands."""
        written, _ = self._attempt("./sub/./../custody/ledger.py")
        self.assertEqual(written, [])

    def test_case_variants_are_refused(self) -> None:
        """Most desktop filesystems fold case; the guard must too."""
        for key in ("CUSTODY/LEDGER.PY", "Custody/Ledger.py", ".CUSTODY/ledger.jsonl"):
            written, _ = self._attempt(key)
            self.assertEqual(written, [], key)

    def test_escaping_the_repository_is_still_refused(self) -> None:
        """The original containment guard still holds."""
        for key in ("../outside.py", "sub/../../outside.py", "/tmp/outside.py"):
            written, _ = self._attempt(key)
            self.assertEqual(written, [], key)
        self.assertFalse((self.root.parent / "outside.py").exists())

    def test_ordinary_writes_are_unaffected(self) -> None:
        """The fix does not block legitimate work."""
        written, refused = _apply(self.root, {"pkg/mod.py": "x = 1\n"})
        self.assertEqual(written, ["pkg/mod.py"])
        self.assertEqual(refused, [])

    def test_any_dotdot_is_refused_even_when_harmless(self) -> None:
        """A traversal segment is refused outright, not canonicalised and allowed.

        ``sub/../pkg/mod.py`` lands somewhere perfectly ordinary. It is still
        refused, because deciding case by case whether a traversal is benign
        is the reasoning that produced the original bypass.
        """
        written, refused = _apply(self.root, {"sub/../pkg/mod.py": "x = 1\n"})
        self.assertEqual(written, [])
        self.assertEqual(refused, ["sub/../pkg/mod.py"])

    def test_written_paths_are_reported_canonically(self) -> None:
        """The ledger records where a write landed, not how it was spelled."""
        written, _ = _apply(self.root, {"./pkg/mod.py": "x = 1\n"})
        self.assertEqual(written, ["pkg/mod.py"])


class PathPredicateTests(unittest.TestCase):
    """The predicates the guard is built from."""

    def test_repo_relative_rejects_traversal_and_absolutes(self) -> None:
        """Syntactic filtering happens before resolution."""
        for bad in ("../a.py", "a/../../b.py", "/etc/passwd", "~/x.py", "C:/x.py", ""):
            self.assertFalse(is_repo_relative(bad), bad)

    def test_repo_relative_accepts_ordinary_paths(self) -> None:
        """Normal paths pass."""
        for good in ("a.py", "pkg/mod.py", "./pkg/mod.py", "a/b/c/d.py"):
            self.assertTrue(is_repo_relative(good), good)

    def test_protection_is_case_insensitive(self) -> None:
        """Over-matching a protected path is safe; under-matching is not."""
        self.assertTrue(is_protected("TESTS/test_a.py"))
        self.assertTrue(is_integrity_critical("Custody/Ledger.py"))
        self.assertTrue(is_integrity_critical(".CUSTODY/ledger.jsonl"))


class LedgerTruncationTests(unittest.TestCase):
    """Dropping the tail of a hash chain leaves a consistent prefix.

    Nothing in entry *k* depends on entry *k+1* having existed, so truncation
    is invisible to the chain alone. A head marker records the expected tail.
    """

    def setUp(self) -> None:
        """Write a six-entry ledger."""
        self.root = Path(tempfile.mkdtemp())
        self.path = self.root / "ledger.jsonl"
        ledger = Ledger(self.path)
        for index in range(6):
            ledger.append("actor", "action-%d" % index)

    def _truncate(self, drop: int) -> None:
        """Remove ``drop`` entries from the end of the file."""
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(lines[:-drop]) + "\n", encoding="utf-8")

    def test_intact_ledger_verifies(self) -> None:
        """The baseline still passes."""
        report = Ledger(self.path).verify()
        self.assertTrue(report.intact)
        self.assertEqual(report.entries, 6)

    def test_tail_truncation_is_detected(self) -> None:
        """A shorter but self-consistent prefix no longer reads as intact."""
        self._truncate(2)
        report = Ledger(self.path).verify()
        self.assertFalse(report.intact)
        self.assertIn("removed from the end", report.reason)
        self.assertEqual(report.expected_entries, 6)

    def test_single_entry_truncation_is_detected(self) -> None:
        """Even one dropped entry disagrees with the marker."""
        self._truncate(1)
        self.assertFalse(Ledger(self.path).verify().intact)

    def test_middle_deletion_is_still_detected(self) -> None:
        """The original chain property is unaffected."""
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")
        self.assertFalse(Ledger(self.path).verify().intact)

    def test_content_forgery_is_still_detected(self) -> None:
        """Editing an entry still breaks its seal."""
        raw = self.path.read_text(encoding="utf-8")
        self.path.write_text(raw.replace("action-0", "action-x"), encoding="utf-8")
        self.assertFalse(Ledger(self.path).verify().intact)

    def test_head_marker_is_maintained_across_reopen(self) -> None:
        """Appending to a reopened ledger keeps the marker current."""
        Ledger(self.path).append("actor", "action-6")
        report = Ledger(self.path).verify()
        self.assertTrue(report.intact)
        self.assertEqual(report.entries, 7)

    def test_missing_marker_is_itself_suspect(self) -> None:
        """Deleting the marker must not reopen the truncation hole.

        Truncating the ledger *and* removing the marker leaves a perfectly
        self-consistent prefix; if a missing marker were accepted as intact,
        one extra deleted file would defeat the whole truncation check. An
        earlier version enshrined exactly that acceptance.
        """
        Ledger(self.path).head_path.unlink()
        report = Ledger(self.path).verify()
        self.assertFalse(report.intact)
        self.assertIn("head marker is missing", report.reason)

    def test_empty_ledger_without_marker_is_intact(self) -> None:
        """A ledger that never recorded anything has nothing to truncate."""
        empty = Ledger(self.root / "fresh.jsonl")
        self.assertTrue(empty.verify().intact)

    def test_rewritten_tail_disagrees_with_marker_hash(self) -> None:
        """A same-length re-chained tail fails against the recorded seal.

        Count comparison alone accepts a forgery that replaces the final
        entries with the same number of re-sealed ones; the marker's recorded
        tail hash is what catches it.
        """
        lines = self.path.read_text(encoding="utf-8").splitlines()
        entries = [json.loads(line) for line in lines]
        forged = dict(entries[-1])
        forged["action"] = "forged-action"
        body = {k: v for k, v in forged.items() if k != "entry_hash"}
        forged["entry_hash"] = digest(canonical_json(body))
        lines[-1] = canonical_json(forged)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = Ledger(self.path).verify()
        self.assertFalse(report.intact)

    def test_malformed_line_reports_broken_not_traceback(self) -> None:
        """Corruption that breaks the entry schema is a verdict, not a crash."""
        raw = self.path.read_text(encoding="utf-8")
        self.path.write_text(raw.replace('"action"', '"bction"', 1), encoding="utf-8")
        with self.assertRaises(LedgerError):
            Ledger(self.path)


class CostBlindSpotTests(unittest.TestCase):
    """An unpriced model must not silently switch the cost check off."""

    def _context(self, **kwargs: object) -> DiffContext:
        """Build a context with cost fields set; spend is priced by default."""
        base = {
            "contract": ScopeContract("C", ["a.py"], "h", "v"),
            "changed": ["a.py"], "before": {"a.py": "x"}, "after": {"a.py": "y"},
            "cost_measurable": True,
        }
        base.update(kwargs)
        return DiffContext(**base)

    def test_unpriced_model_produces_a_finding(self) -> None:
        """Pricing failure is reported rather than read as free work."""
        detections = detect_cost_underreport(
            self._context(declared_cost_usd=0.0, measured_cost_usd=0.0, cost_measurable=False)
        )
        self.assertEqual([d.detector for d in detections], ["cost-unverifiable"])

    def test_unverifiable_message_refuses_the_free_claim(self) -> None:
        """The wording does not let a reader infer the attempt was free."""
        detection = detect_cost_underreport(
            self._context(cost_measurable=False)
        )[0]
        self.assertIn("not a confirmation", detection.message)

    def test_underreporting_is_still_critical(self) -> None:
        """The original detector is unchanged for priced models."""
        detections = detect_cost_underreport(
            self._context(declared_cost_usd=0.001, measured_cost_usd=0.05)
        )
        self.assertEqual([d.detector for d in detections], ["cost-underreport"])

    def test_accurate_priced_spend_is_quiet(self) -> None:
        """No finding when the declaration matches the measurement."""
        self.assertEqual(
            detect_cost_underreport(
                self._context(declared_cost_usd=0.05, measured_cost_usd=0.05)
            ),
            [],
        )

    def test_genuinely_free_priced_work_is_quiet(self) -> None:
        """A deterministic remediator costs nothing and is not accused."""
        self.assertEqual(
            detect_cost_underreport(
                self._context(declared_cost_usd=0.0, measured_cost_usd=0.0)
            ),
            [],
        )


class AliasBlindnessTests(unittest.TestCase):
    """Renaming an import must not hide a dangerous call."""

    def setUp(self) -> None:
        """Create a scratch directory."""
        self.root = Path(tempfile.mkdtemp())

    def _rules(self, source: str) -> set:
        """Return security rules firing on ``source``."""
        path = self.root / "m.py"
        path.write_text(source, encoding="utf-8")
        return {
            f.rule for f in survey_source(path, "m.py")
            if f.rule.startswith(("dangerous", "subprocess"))
        }

    def test_aliased_module_is_resolved(self) -> None:
        """Import os as o still reports o.system."""
        self.assertIn(
            "dangerous-call-os-system",
            self._rules('import os as o\n\n\ndef f(c: str) -> int:\n    """D."""\n'
                        '    return o.system(c)\n'),
        )

    def test_aliased_symbol_is_resolved(self) -> None:
        """From os import system as run still reports run()."""
        self.assertIn(
            "dangerous-call-os-system",
            self._rules('from os import system as run\n\n\ndef f(c: str) -> int:\n'
                        '    """D."""\n    return run(c)\n'),
        )

    def test_aliased_deserialisation_is_resolved(self) -> None:
        """Renamed pickle is still pickle."""
        self.assertIn(
            "dangerous-call-pickle-loads",
            self._rules('import pickle as pk\n\n\ndef f(b: bytes) -> object:\n'
                        '    """D."""\n    return pk.loads(b)\n'),
        )

    def test_non_literal_shell_is_reported_not_ignored(self) -> None:
        """An unprovable shell is surfaced at lower severity."""
        self.assertIn(
            "subprocess-shell-unresolved",
            self._rules('import subprocess\n\n\ndef f(a: list, flag: bool) -> None:\n'
                        '    """D."""\n    subprocess.run(a, shell=flag)\n'),
        )

    def test_kwargs_spread_is_reported(self) -> None:
        """A spread could carry a shell keyword, and that is said."""
        self.assertIn(
            "subprocess-shell-unresolved",
            self._rules('import subprocess\n\n\ndef f(a: list, kw: dict) -> None:\n'
                        '    """D."""\n    subprocess.run(a, **kw)\n'),
        )

    def test_literal_spread_without_shell_is_quiet(self) -> None:
        """A spread the rule can read is judged on its contents."""
        self.assertEqual(
            self._rules('import subprocess\n\n\ndef f(a: list) -> None:\n    """D."""\n'
                        '    subprocess.run(a, **{"check": True})\n'),
            set(),
        )

    def test_safe_alternatives_remain_quiet(self) -> None:
        """Alias resolution does not create false positives."""
        self.assertEqual(
            self._rules('import ast as a\nimport yaml as y\n\n\n'
                        'def f(s: str) -> object:\n    """D."""\n'
                        '    return a.literal_eval(s) or y.safe_load(s)\n'),
            set(),
        )


if __name__ == "__main__":
    unittest.main()
