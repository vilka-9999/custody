"""Tests for the model reviewer: a one-way ratchet over ambiguous rulings."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from custody import gitio
from custody.auditor.detectors import Detection, DiffContext
from custody.auditor.review import (
    SecondOpinion,
    build_review_prompt,
    needs_review,
    parse_opinion,
)
from custody.auditor.verdict import Judgment, Ruling
from custody.findings import Finding, Pillar, Severity
from custody.harness import Proposal, run_case
from custody.ledger import Ledger
from custody.remediator.contract import ScopeContract

SRC = "app.py"


def _finding(finding_id: str = "CUS-1") -> Finding:
    """Return the finding under adjudication."""
    return Finding(finding_id, "bare-except", Pillar.QUALITY, Severity.MEDIUM, SRC, 1, "m")


def _judgment(ruling: Ruling, detections: list[Detection]) -> Judgment:
    """Build a judgment carrying ``detections``."""
    return Judgment("CUS-1", ruling, "reason", detections)


def _advisory() -> Detection:
    """One advisory (non-critical) detection."""
    return Detection("suppression-added", Severity.HIGH, SRC, "added a noqa")


class NeedsReviewTests(unittest.TestCase):
    """Only one state is ambiguous."""

    def test_proven_with_advisory_detections_is_ambiguous(self) -> None:
        """Deterministically clean plus recorded suspicion needs a reviewer."""
        self.assertTrue(needs_review(_judgment(Ruling.PROVEN, [_advisory()])))

    def test_clean_proven_needs_no_review(self) -> None:
        """With nothing flagged there is nothing to weigh."""
        self.assertFalse(needs_review(_judgment(Ruling.PROVEN, [])))

    def test_decided_rulings_need_no_review(self) -> None:
        """A rejection is decided; nothing uncommitted can be withheld."""
        for ruling in (Ruling.REJECTED, Ruling.NOT_OBSERVED, Ruling.INSUFFICIENT_EVIDENCE):
            self.assertFalse(needs_review(_judgment(ruling, [_advisory()])))


class ParseTests(unittest.TestCase):
    """Malformed model output is never coerced into a verdict."""

    def test_valid_objection_parses(self) -> None:
        """A well-formed objection carries its reason."""
        opinion = parse_opinion({"objects": True, "concern": "the noqa hides a real error"})
        self.assertIsNotNone(opinion)
        assert opinion is not None
        self.assertTrue(opinion.objects)
        self.assertIn("noqa", opinion.concern)

    def test_valid_approval_parses(self) -> None:
        """A well-formed approval is an answer too."""
        opinion = parse_opinion({"objects": False, "concern": "benign"})
        self.assertIsNotNone(opinion)
        assert opinion is not None
        self.assertFalse(opinion.objects)

    def test_missing_or_nonboolean_objects_is_none(self) -> None:
        """Neither direction is guessed from noise."""
        for payload in (None, {}, {"objects": "yes"}, {"objects": 1}, {"concern": "x"}):
            self.assertIsNone(parse_opinion(payload))

    def test_opinion_serialises_for_the_ledger(self) -> None:
        """The recorded form carries the decision, reason, and accounting."""
        opinion = SecondOpinion(True, "why", model="m", cost_usd=0.01, tokens_in=5, tokens_out=7)
        recorded = opinion.to_dict()
        self.assertTrue(recorded["objects"])
        self.assertEqual(recorded["tokens_out"], 7)


class PromptTests(unittest.TestCase):
    """The reviewer sees artifacts, not the remediator's prose."""

    def test_prompt_carries_detections_and_diffs(self) -> None:
        """Contract, detections, and bounded excerpts are all present."""
        ctx = DiffContext(
            contract=ScopeContract("CUS-1", [SRC], "h", "v"),
            changed=[SRC],
            before={SRC: "old code"},
            after={SRC: "new code  # noqa"},
        )
        prompt = build_review_prompt(ctx, _judgment(Ruling.PROVEN, [_advisory()]))
        self.assertIn("suppression-added", prompt)
        self.assertIn("old code", prompt)
        self.assertIn("new code", prompt)
        self.assertIn(SRC, prompt)


def _trial_repo() -> tuple[Path, str, Finding]:
    """Build a scratch repo whose finding a scripted attempt will clear."""
    root = Path(tempfile.mkdtemp())
    (root / "tests").mkdir()
    (root / SRC).write_text(
        "def f():\n    try:\n        pass\n    except:\n        pass\n", encoding="utf-8"
    )
    (root / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (root / "tests" / "test_app.py").write_text(
        '"""T."""\n\nimport unittest\n\n\nclass T(unittest.TestCase):\n'
        '    """T."""\n\n    def test_ok(self) -> None:\n'
        '        """Ok."""\n        self.assertEqual(1 + 1, 2)\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", "-b", "work", str(root)], check=True)
    for key, value in (("user.email", "t@t"), ("user.name", "t")):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
    sha = gitio.commit_all(root, "seed")

    from custody.surveyor.runner import survey

    finding = next(f for f in survey(root).findings if f.rule == "bare-except")
    return root, sha, finding


def _fix_with_suppression(finding: Finding) -> Proposal:
    """An honest fix that also smuggles in a suppression comment.

    This lands in the one ambiguous state: the finding clears, the suite is
    green, the scope is respected - and suppression-added fires as advisory.
    """
    fixed = (
        "def f():  # noqa\n    try:\n        pass\n    except Exception:\n        pass\n"
    )
    return Proposal(
        contract=ScopeContract(finding.id, [SRC], "narrow the handler", "suite stays green"),
        files={SRC: fixed},
    )


class RatchetTests(unittest.TestCase):
    """The reviewer can withhold a commit; it can never mint one."""

    def _run(self, review):  # type: ignore[no-untyped-def]
        root, sha, finding = _trial_repo()
        ledger = Ledger(root / ".custody" / "ledger.jsonl")
        from custody.surveyor.runner import survey

        result = run_case(
            root, finding, _fix_with_suppression(finding), ledger, sha,
            survey(root).findings, commit=True, review=review,
        )
        actions = [entry.action for entry in ledger.read()]
        return result, actions

    def test_objection_withholds_the_commit(self) -> None:
        """PROVEN stands, the commit does not."""
        result, actions = self._run(
            lambda _ctx, _judgment: SecondOpinion(True, "suppression is doing the work")
        )
        self.assertIs(result.judgment.ruling, Ruling.PROVEN)
        self.assertFalse(result.committed)
        self.assertIn("review.completed", actions)

    def test_approval_lets_the_deterministic_ruling_proceed(self) -> None:
        """An approving reviewer changes nothing."""
        result, actions = self._run(
            lambda _ctx, _judgment: SecondOpinion(False, "benign in context")
        )
        self.assertIs(result.judgment.ruling, Ruling.PROVEN)
        self.assertTrue(result.committed)
        self.assertIn("review.completed", actions)

    def test_unreachable_reviewer_is_recorded_not_fatal(self) -> None:
        """A failed review is a recorded gap; the deterministic ruling stands."""
        result, actions = self._run(lambda _ctx, _judgment: None)
        self.assertTrue(result.committed)
        self.assertIn("review.unavailable", actions)

    def test_no_reviewer_means_no_review_entries(self) -> None:
        """Offline runs behave exactly as before the reviewer existed."""
        result, actions = self._run(None)
        self.assertTrue(result.committed)
        self.assertNotIn("review.completed", actions)
        self.assertNotIn("review.unavailable", actions)

    def test_reviewer_is_never_consulted_on_a_clean_proven(self) -> None:
        """No ambiguity, no model call - the audit stays deterministic."""
        root, sha, finding = _trial_repo()
        ledger = Ledger(root / ".custody" / "ledger.jsonl")
        clean = Proposal(
            contract=ScopeContract(finding.id, [SRC], "narrow the handler", "suite green"),
            files={SRC: "def f():\n    try:\n        pass\n"
                        "    except Exception:\n        pass\n"},
        )
        calls: list[str] = []

        def spy(_ctx: DiffContext, _judgment: Judgment) -> SecondOpinion:
            """Record that the reviewer was consulted."""
            calls.append("called")
            return SecondOpinion(True, "should never happen")

        from custody.surveyor.runner import survey

        result = run_case(
            root, finding, clean, ledger, sha, survey(root).findings,
            commit=True, review=spy,
        )
        self.assertTrue(result.committed)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
