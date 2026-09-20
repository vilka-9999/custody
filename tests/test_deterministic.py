"""Tests for the rule-based remediator, which declines rather than guesses."""

import tempfile
import unittest
from pathlib import Path

from custody.findings import Finding, Pillar, Severity
from custody.remediator import deterministic
from custody.remediator.deterministic import (
    can_fix,
    fix_bare_except,
    fix_missing_docstring,
    fix_shell_true,
)


def finding(rule: str, path: str, line: int, **detail: object) -> Finding:
    """Build a finding to fix."""
    return Finding(
        "CUS-1", rule, Pillar.QUALITY, Severity.LOW, path, line, "message", detail=detail
    )


class ShellTrueTests(unittest.TestCase):
    """Dropping shell=True is only safe for an argument list."""

    def test_argument_list_is_fixed(self) -> None:
        """A list argument loses the shell keyword."""
        source = "import subprocess\n\n\ndef f(a):\n    return subprocess.run(a, shell=True)\n"
        fixed = fix_shell_true(source, finding("subprocess-shell-true", "a.py", 5))
        self.assertIsNotNone(fixed)
        self.assertNotIn("shell=True", fixed or "")

    def test_command_string_is_declined(self) -> None:
        """Rewriting a command string into a list is a semantic change."""
        source = 'import subprocess\n\n\ndef f():\n    return subprocess.run("ls -l", shell=True)\n'
        self.assertIsNone(fix_shell_true(source, finding("subprocess-shell-true", "a.py", 5)))

    def test_out_of_range_line_is_declined(self) -> None:
        """A stale location never edits the wrong line."""
        self.assertIsNone(fix_shell_true("x = 1\n", finding("subprocess-shell-true", "a.py", 99)))

    def test_line_without_the_keyword_is_declined(self) -> None:
        """A finding pointing at the wrong line changes nothing."""
        source = "x = 1\ny = 2\n"
        self.assertIsNone(fix_shell_true(source, finding("subprocess-shell-true", "a.py", 1)))


class BareExceptTests(unittest.TestCase):
    """Narrowing a handler preserves intent."""

    def test_bare_handler_is_narrowed(self) -> None:
        """except: becomes except Exception:."""
        source = "def f():\n    try:\n        pass\n    except:\n        pass\n"
        fixed = fix_bare_except(source, finding("bare-except", "a.py", 4))
        self.assertIn("except Exception:", fixed or "")

    def test_indentation_is_preserved(self) -> None:
        """The replacement keeps the original indentation exactly."""
        source = "class C:\n    def f(self):\n        try:\n            pass\n        except:\n            pass\n"
        fixed = fix_bare_except(source, finding("bare-except", "a.py", 5))
        self.assertIn("        except Exception:", fixed or "")

    def test_already_narrow_handler_is_declined(self) -> None:
        """A typed handler is left alone."""
        source = "def f():\n    try:\n        pass\n    except ValueError:\n        pass\n"
        self.assertIsNone(fix_bare_except(source, finding("bare-except", "a.py", 4)))


class DocstringTests(unittest.TestCase):
    """Inserting a docstring without disturbing the body."""

    def test_function_gains_a_docstring(self) -> None:
        """A minimal docstring is inserted at the top of the body."""
        source = "def compute(a):\n    return a\n"
        fixed = fix_missing_docstring(source, finding("missing-docstring", "a.py", 1))
        self.assertIsNotNone(fixed)
        self.assertIn('"""', fixed or "")

    def test_documented_function_is_declined(self) -> None:
        """An existing docstring is never duplicated."""
        source = 'def compute(a):\n    """Doc."""\n    return a\n'
        self.assertIsNone(fix_missing_docstring(source, finding("missing-docstring", "a.py", 1)))

    def test_unparsable_source_is_declined(self) -> None:
        """Broken syntax is never edited."""
        self.assertIsNone(
            fix_missing_docstring("def (:\n", finding("missing-docstring", "a.py", 1))
        )

    def test_stale_line_is_declined(self) -> None:
        """A location that no longer names a function changes nothing."""
        source = "def compute(a):\n    return a\n"
        self.assertIsNone(fix_missing_docstring(source, finding("missing-docstring", "a.py", 9)))


class ScopeTests(unittest.TestCase):
    """Protected territory is declined before a proposal is built."""

    def test_protected_paths_are_not_fixable(self) -> None:
        """Even a trivially fixable rule is declined inside a test file."""
        self.assertFalse(can_fix(finding("missing-docstring", "tests/test_a.py", 1)))
        self.assertFalse(can_fix(finding("bare-except", ".github/workflows/ci.yml", 1)))

    def test_ordinary_paths_are_fixable(self) -> None:
        """Normal source is in scope."""
        self.assertTrue(can_fix(finding("missing-docstring", "pkg/mod.py", 1)))

    def test_unknown_rule_is_not_fixable(self) -> None:
        """No fixer means no proposal."""
        self.assertFalse(can_fix(finding("some-future-rule", "pkg/mod.py", 1)))


class ProposalTests(unittest.TestCase):
    """A proposal is only produced when the result actually parses."""

    def test_proposal_declares_only_the_target_file(self) -> None:
        """Authority is scoped to the file being fixed."""
        root = Path(tempfile.mkdtemp())
        (root / "a.py").write_text("def f(a):\n    return a\n", encoding="utf-8")
        proposal = deterministic.propose(root, finding("missing-docstring", "a.py", 1))
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.contract.allowed_paths, ["a.py"])

    def test_missing_file_is_declined(self) -> None:
        """A finding pointing at a vanished file yields nothing."""
        root = Path(tempfile.mkdtemp())
        self.assertIsNone(deterministic.propose(root, finding("bare-except", "gone.py", 1)))

    def test_no_change_is_declined(self) -> None:
        """A fixer that would produce identical text proposes nothing."""
        root = Path(tempfile.mkdtemp())
        (root / "a.py").write_text('def f(a):\n    """D."""\n    return a\n', encoding="utf-8")
        self.assertIsNone(deterministic.propose(root, finding("missing-docstring", "a.py", 1)))


if __name__ == "__main__":
    unittest.main()
