"""Tests for the console, including a live HTTP request against it."""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

from custody.console import ConsoleHandler, render, summarise
from custody.ledger import Ledger


def populated_ledger(root: Path) -> Ledger:
    """Return a ledger with one full case recorded."""
    ledger = Ledger(root / "ledger.jsonl")
    ledger.append("harness", "case.opened", target="CUS-1")
    ledger.append("remediator", "contract.declared", target="CUS-1", cost_usd=0.031)
    ledger.append(
        "remediator", "files.written", target="CUS-1", files_touched=["app.py"]
    )
    ledger.append("auditor", "case.ruled", target="CUS-1", verdict="PROVEN")
    ledger.append("auditor", "case.ruled", target="CUS-2", verdict="REJECTED")
    return ledger


class RenderTests(unittest.TestCase):
    """The page reports the chain honestly."""

    def setUp(self) -> None:
        """Create a populated ledger in a temporary directory."""
        self.root = Path(tempfile.mkdtemp())
        self.ledger = populated_ledger(self.root)

    def test_intact_chain_is_stated(self) -> None:
        """A verified chain says so."""
        self.assertIn("Chain intact", render(self.ledger))

    def test_broken_chain_is_surfaced_not_hidden(self) -> None:
        """A forged ledger cannot render as a clean page."""
        path = self.root / "ledger.jsonl"
        path.write_text(
            path.read_text(encoding="utf-8").replace("PROVEN", "REJECTED"), encoding="utf-8"
        )
        page = render(Ledger(path))
        self.assertIn("CHAIN BROKEN", page)
        self.assertNotIn("Chain intact", page)

    def test_rulings_and_spend_are_counted(self) -> None:
        """Headline numbers come from the entries, not from a summary field."""
        stats = summarise(list(self.ledger.read()))
        self.assertEqual(stats["rulings"], {"PROVEN": 1, "REJECTED": 1})
        self.assertAlmostEqual(float(stats["spend"]), 0.031, places=4)
        self.assertEqual(stats["files"], 1)

    def test_empty_ledger_renders_without_error(self) -> None:
        """A page with nothing to show still renders."""
        empty = Ledger(Path(tempfile.mkdtemp()) / "l.jsonl")
        self.assertIn("No entries yet", render(empty))

    def test_html_in_a_target_is_escaped(self) -> None:
        """Ledger content is data; it never becomes markup."""
        ledger = Ledger(Path(tempfile.mkdtemp()) / "l.jsonl")
        ledger.append("remediator", "files.written", target="<script>alert(1)</script>")
        page = render(ledger)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


class ServerTests(unittest.TestCase):
    """The handler answers real requests."""

    def setUp(self) -> None:
        """Start the console on an ephemeral port."""
        self.root = Path(tempfile.mkdtemp())
        populated_ledger(self.root)
        ConsoleHandler.ledger_path = self.root / "ledger.jsonl"
        self.server = HTTPServer(("127.0.0.1", 0), ConsoleHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        """Stop the console."""
        self.server.shutdown()
        self.server.server_close()

    def _get(self, path: str) -> tuple:
        """Fetch a path and return status and body."""
        with urllib.request.urlopen(
            "http://127.0.0.1:%d%s" % (self.port, path), timeout=5
        ) as response:
            return response.status, response.read().decode("utf-8")

    def test_index_serves_the_dashboard(self) -> None:
        """The root path returns the rendered page."""
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("Custody", body)
        self.assertIn("Chain intact", body)

    def test_json_feed_reports_the_chain(self) -> None:
        """The JSON view carries every entry and the verification result."""
        status, body = self._get("/ledger.json")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["intact"])
        self.assertEqual(len(payload["entries"]), 5)
        self.assertIn("entry_hash", payload["entries"][0])

    def test_json_entries_carry_their_seals(self) -> None:
        """A consumer can re-verify the chain from the feed alone."""
        payload = json.loads(self._get("/ledger.json")[1])
        hashes = [entry["entry_hash"] for entry in payload["entries"]]
        prevs = [entry["prev_hash"] for entry in payload["entries"]]
        self.assertEqual(hashes[:-1], prevs[1:])

    def test_unknown_path_is_a_404(self) -> None:
        """The console serves two things and nothing else."""
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._get("/../../etc/passwd")
        self.assertEqual(caught.exception.code, 404)

    def test_non_loopback_host_header_is_refused(self) -> None:
        """A rebinding page's hostname does not read the ledger.

        The bind address is loopback, but DNS rebinding lets a remote page
        resolve its own hostname to 127.0.0.1; the Host header is the tell.
        """
        request = urllib.request.Request(
            "http://127.0.0.1:%d/ledger.json" % self.port,
            headers={"Host": "evil.example.com"},
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 403)

    def test_localhost_host_header_is_allowed(self) -> None:
        """The operator's own browser bar keeps working."""
        request = urllib.request.Request(
            "http://127.0.0.1:%d/" % self.port,
            headers={"Host": "localhost:%d" % self.port},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main()
