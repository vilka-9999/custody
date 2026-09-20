"""Tests for scope-contract validation and enforcement."""

import unittest
from collections.abc import Iterable

from custody.remediator.contract import (
    MAX_DECLARED_PATHS,
    ScopeContract,
    ScopeViolationError,
    check_scope,
    is_protected,
    validate_contract,
)


def contract(paths: Iterable[str], finding_id: str = "CUS-1") -> ScopeContract:
    """Build a contract over ``paths`` for testing."""
    return ScopeContract(finding_id, list(paths), "hypothesis", "verification", "0" * 40)


class ValidationTests(unittest.TestCase):
    """A contract is checked before the agent is allowed to act."""

    def test_ordinary_source_path_is_accepted(self) -> None:
        """A normal source file may be declared."""
        validate_contract(contract(["custody/surveyor/secrets.py"]))

    def test_test_paths_are_rejected(self) -> None:
        """Tests may never be declared writable."""
        for path in ("tests/test_x.py", "pkg/test_helper.py", "pkg/helper_test.py"):
            with self.assertRaises(ScopeViolationError):
                validate_contract(contract([path]))

    def test_config_and_ci_are_rejected(self) -> None:
        """Quality gates and CI definitions are off limits."""
        for path in ("pyproject.toml", "setup.cfg", ".github/workflows/ci.yml"):
            with self.assertRaises(ScopeViolationError):
                validate_contract(contract([path]))

    def test_auditor_and_ledger_are_rejected(self) -> None:
        """An agent may not edit its judge or its record."""
        for path in ("custody/auditor/detectors.py", "custody/ledger.py"):
            with self.assertRaises(ScopeViolationError):
                validate_contract(contract([path]))

    def test_path_traversal_is_rejected(self) -> None:
        """Declared paths may not leave the repository."""
        for path in ("../secrets.py", "/etc/passwd"):
            with self.assertRaises(ScopeViolationError):
                validate_contract(contract([path]))

    def test_empty_declaration_is_rejected(self) -> None:
        """An attempt must say what it intends to write."""
        with self.assertRaises(ScopeViolationError):
            validate_contract(contract([]))

    def test_overbroad_declaration_is_rejected(self) -> None:
        """An attempt too wide to adjudicate is refused up front."""
        paths = ["pkg/mod_%d.py" % index for index in range(MAX_DECLARED_PATHS + 1)]
        with self.assertRaises(ScopeViolationError):
            validate_contract(contract(paths))


class EnforcementTests(unittest.TestCase):
    """What actually changed is compared against what was declared."""

    def test_declared_file_is_permitted(self) -> None:
        """Writing the declared file produces no violation."""
        self.assertEqual(check_scope(contract(["a/b.py"]), ["a/b.py"]), [])

    def test_undeclared_file_is_a_violation(self) -> None:
        """Writing anything else is caught."""
        self.assertEqual(check_scope(contract(["a/b.py"]), ["a/c.py"]), ["a/c.py"])

    def test_protected_file_is_a_violation_even_if_declared(self) -> None:
        """A protected path is refused whatever the contract claims."""
        sneaky = ScopeContract("CUS-1", ["tests/test_x.py"], "h", "v")
        self.assertEqual(check_scope(sneaky, ["tests/test_x.py"]), ["tests/test_x.py"])

    def test_wildcard_declarations_are_rejected(self) -> None:
        """A declared pattern is not a declaration; it must name a file.

        ``**`` matches no protected glob as a string, yet every later write
        falls inside it - a contract that validates while making scope-escape
        unable to fire. Patterns are therefore refused at validation.
        """
        for wildcard in ("**", "custody/surveyor/*.py", "src/?.py", "src/[ab].py"):
            with self.assertRaises(ScopeViolationError):
                validate_contract(contract([wildcard]))

    def test_undeclared_glob_grants_no_authority(self) -> None:
        """A pattern that slips past validation still permits nothing."""
        self.assertEqual(
            check_scope(contract(["custody/surveyor/*.py"]), ["custody/surveyor/secrets.py"]),
            ["custody/surveyor/secrets.py"],
        )

    def test_scope_matching_is_case_insensitive(self) -> None:
        """Authority matching folds case, like the protection globs do."""
        self.assertEqual(check_scope(contract(["a/b.py"]), ["A/B.py"]), [])

    def test_is_protected_recognises_nested_paths(self) -> None:
        """Protection applies to files nested under a protected directory."""
        self.assertTrue(is_protected(".github/workflows/nested/ci.yml"))
        self.assertFalse(is_protected("custody/surveyor/ast_rules.py"))


if __name__ == "__main__":
    unittest.main()
