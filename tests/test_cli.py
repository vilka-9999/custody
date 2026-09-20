"""Tests for CLI helpers that survive repository drift."""

import unittest

from custody.cli import _key, build_parser
from custody.findings import Finding, Pillar, Severity


def finding(rule: str, path: str, line: int, **detail: object) -> Finding:
    """Build a finding for identity testing."""
    return Finding("CUS-X", rule, Pillar.QUALITY, Severity.LOW, path, line, "m", detail=detail)


class IdentityTests(unittest.TestCase):
    """A finding's identity must survive line-number drift."""

    def test_symbol_identity_ignores_line_movement(self) -> None:
        """The same symbol at a new line is the same finding."""
        before = finding("missing-docstring", "a.py", 16, symbol="Registry")
        after = finding("missing-docstring", "a.py", 17, symbol="Registry")
        self.assertEqual(_key(before), _key(after))

    def test_different_symbols_are_distinct(self) -> None:
        """Two undocumented symbols in one file are two findings."""
        self.assertNotEqual(
            _key(finding("missing-docstring", "a.py", 1, symbol="A")),
            _key(finding("missing-docstring", "a.py", 1, symbol="B")),
        )

    def test_function_detail_is_honoured(self) -> None:
        """Rules recording 'function' rather than 'symbol' key on it too."""
        self.assertEqual(
            _key(finding("high-complexity", "a.py", 5, function="parse")),
            _key(finding("high-complexity", "a.py", 90, function="parse")),
        )

    def test_line_is_the_fallback(self) -> None:
        """Rules with no symbol fall back to location."""
        self.assertEqual(_key(finding("bare-except", "a.py", 12)),
                         ("bare-except", "a.py", 12))

    def test_same_rule_in_different_files_is_distinct(self) -> None:
        """Path is part of identity."""
        self.assertNotEqual(
            _key(finding("bare-except", "a.py", 1)),
            _key(finding("bare-except", "b.py", 1)),
        )


class ParserTests(unittest.TestCase):
    """The CLI exposes every command and refuses an empty invocation."""

    def test_every_command_is_registered(self) -> None:
        """All six subcommands parse."""
        parser = build_parser()
        for command in ("survey", "verify", "eval", "trial", "console", "harden"):
            self.assertTrue(parser.parse_args([command]))

    def test_harden_defaults_are_conservative(self) -> None:
        """Committing to a default branch is off unless asked for."""
        args = build_parser().parse_args(["harden"])
        self.assertFalse(args.allow_default_branch)
        self.assertFalse(args.dry_run)
        self.assertEqual(args.model, "claude-opus-5")

    def test_no_command_is_an_error(self) -> None:
        """A bare invocation does not silently do something."""
        with self.assertRaises(SystemExit):
            build_parser().parse_args([])


if __name__ == "__main__":
    unittest.main()
