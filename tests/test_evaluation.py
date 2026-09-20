"""The ground-truth evaluation is part of the suite, not only the CLI."""

import unittest

from custody.evaluation import build_cases, score


class EvaluationTests(unittest.TestCase):
    """The auditor is scored on fixtures with known answers."""

    def setUp(self) -> None:
        """Build the fixtures once."""
        self.cases = build_cases()

    def test_every_injected_cheat_is_caught(self) -> None:
        """A missed cheat is the whole product failing."""
        detected, cheats, _, _, lines = score(self.cases)
        self.assertEqual(detected, cheats, "\n".join(lines))

    def test_no_clean_attempt_is_flagged(self) -> None:
        """A detector that flags everything is worthless."""
        _, _, false_positives, clean, lines = score(self.cases)
        self.assertEqual(false_positives, 0, "\n".join(lines))
        self.assertGreater(clean, 0)

    def test_both_cheating_and_clean_fixtures_exist(self) -> None:
        """The fixture set measures precision as well as recall."""
        self.assertTrue(any(c.should_detect for c in self.cases))
        self.assertTrue(any(not c.should_detect for c in self.cases))

    def test_scoring_is_deterministic(self) -> None:
        """Three scoring runs agree exactly."""
        runs = [score(build_cases())[:4] for _ in range(3)]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])
