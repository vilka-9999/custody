"""Tests for the tamper-evident ledger."""

import json
import tempfile
import unittest
from pathlib import Path

from custody.ledger import GENESIS_HASH, Ledger, canonical_json, verify_chain


class LedgerTests(unittest.TestCase):
    """Behaviour of append, resume and verification."""

    def setUp(self) -> None:
        """Create an empty ledger in a temporary directory."""
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "ledger.jsonl"
        self.ledger = Ledger(self.path)

    def test_first_entry_links_to_genesis(self) -> None:
        """The opening entry chains to the all-zero genesis hash."""
        entry = self.ledger.append("surveyor", "survey.started")
        self.assertEqual(entry.prev_hash, GENESIS_HASH)
        self.assertEqual(entry.seq, 0)
        self.assertTrue(entry.entry_hash)

    def test_entries_chain_in_order(self) -> None:
        """Each entry's prev_hash is the previous entry's seal."""
        first = self.ledger.append("surveyor", "a")
        second = self.ledger.append("remediator", "b")
        self.assertEqual(second.prev_hash, first.entry_hash)
        self.assertEqual(second.seq, 1)

    def test_intact_chain_verifies(self) -> None:
        """An unmodified ledger verifies clean."""
        for index in range(5):
            self.ledger.append("auditor", "ruling", target="CUS-%d" % index)
        report = self.ledger.verify()
        self.assertTrue(report.intact)
        self.assertEqual(report.entries, 5)

    def test_edited_entry_is_detected(self) -> None:
        """Changing a recorded action breaks that entry's seal."""
        self.ledger.append("remediator", "fix.applied", target="CUS-1")
        self.ledger.append("auditor", "ruling", verdict="PROVEN")
        lines = self.path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["action"] = "fix.notapplied"
        lines[0] = canonical_json(tampered)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = Ledger(self.path).verify()
        self.assertFalse(report.intact)
        self.assertEqual(report.broken_at, 0)

    def test_deleted_entry_is_detected(self) -> None:
        """Removing a middle entry breaks the sequence."""
        for index in range(3):
            self.ledger.append("actor", "action-%d" % index)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        del lines[1]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = Ledger(self.path).verify()
        self.assertFalse(report.intact)

    def test_appending_after_reopen_continues_the_chain(self) -> None:
        """A reopened ledger resumes from the existing tail."""
        self.ledger.append("actor", "first")
        reopened = Ledger(self.path)
        entry = reopened.append("actor", "second")
        self.assertEqual(entry.seq, 1)
        self.assertTrue(reopened.verify().intact)

    def test_cost_is_totalled(self) -> None:
        """Spend recorded across entries sums exactly."""
        self.ledger.append("remediator", "call", cost_usd=0.01)
        self.ledger.append("auditor", "call", cost_usd=0.025)
        self.assertAlmostEqual(self.ledger.total_cost(), 0.035, places=6)

    def test_empty_chain_is_intact(self) -> None:
        """A ledger with no entries is trivially consistent."""
        self.assertTrue(verify_chain([]).intact)


if __name__ == "__main__":
    unittest.main()
