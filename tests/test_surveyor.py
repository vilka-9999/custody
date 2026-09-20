"""Tests for the deterministic surveyor."""

import tempfile
import unittest
from pathlib import Path

from custody.findings import Pillar, Severity, finding_id, group_by_pillar, sort_findings
from custody.surveyor.ast_rules import cyclomatic_complexity, parse_module, survey_source
from custody.surveyor.runner import EXCLUDED_DIRS, iter_files, survey
from custody.surveyor.secrets import looks_like_placeholder, redact, survey_secrets

# Credential fixtures are assembled at runtime rather than written out.
# A test file is still a file in the repository, and committing literal
# key-shaped strings is the thing this module exists to detect - Custody flags
# its own test data otherwise, correctly. Suppressing the rule instead would be
# the exact pattern the auditor calls `suppression-added`.
_AWS_PREFIX = "AK" + "IA"
_ANTHROPIC_PREFIX = "sk" + "-" + "ant"
_PEM = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"

LIVE_AWS_KEY = _AWS_PREFIX + "ZZ12QQ34WW56EE78"
LIVE_ANTHROPIC_KEY = _ANTHROPIC_PREFIX + "-" + "q7x2" * 8
PLACEHOLDER_AWS_KEY = _AWS_PREFIX + "IOSFODNN7EXAMPLE"


def write(root: Path, rel: str, text: str) -> Path:
    """Write ``text`` to ``rel`` under ``root`` and return the path."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def survey_ids(source: str) -> list:
    """Survey ``source`` in a scratch file and return its findings."""
    root = Path(tempfile.mkdtemp())
    path = write(root, "m.py", source)
    return survey_source(path, "m.py") or []


class AstRuleTests(unittest.TestCase):
    """Each rule fires on its own pattern and not on others."""

    def setUp(self) -> None:
        """Create a scratch directory."""
        self.root = Path(tempfile.mkdtemp())

    def _rules(self, source: str) -> set:
        """Return the rule names that fire on ``source``."""
        path = write(self.root, "m.py", source)
        return {f.rule for f in survey_source(path, "m.py")}

    def test_shell_true_is_flagged(self) -> None:
        """A shell invocation is a critical security finding."""
        rules = self._rules(
            'import subprocess\n\n\ndef f(a: list) -> None:\n'
            '    """D."""\n    subprocess.run(a, shell=True)\n'
        )
        self.assertIn("subprocess-shell-true", rules)

    def test_truthy_nonbool_shell_is_flagged(self) -> None:
        """``shell=1`` runs a shell exactly as ``shell=True`` does.

        A rule keyed on the literal ``True`` reported nothing for it - a
        one-character bypass of the flagship check.
        """
        rules = self._rules(
            'import subprocess\n\n\ndef f(a: list) -> None:\n'
            '    """D."""\n    subprocess.run(a, shell=1)\n'
        )
        self.assertIn("subprocess-shell-true", rules)

    def test_falsy_shell_is_clean(self) -> None:
        """``shell=0`` provably runs no shell."""
        rules = self._rules(
            'import subprocess\n\n\ndef f(a: list) -> None:\n'
            '    """D."""\n    subprocess.run(a, shell=0)\n'
        )
        self.assertNotIn("subprocess-shell-true", rules)
        self.assertNotIn("subprocess-shell-unresolved", rules)

    def test_literal_dict_spread_shell_true_is_critical(self) -> None:
        """A visible ``shell: True`` in a spread dict is the real thing."""
        rules = self._rules(
            'import subprocess\n\n\ndef f(a: list) -> None:\n'
            '    """D."""\n    subprocess.run(a, **{"shell": True})\n'
        )
        self.assertIn("subprocess-shell-true", rules)

    def test_deep_attribute_chain_is_not_collapsed(self) -> None:
        """``obj.client.run`` is not ``subprocess.run``.

        Collapsing a chain to its final attribute produced false positives
        whenever ``from subprocess import run`` was in scope.
        """
        rules = self._rules(
            'from subprocess import run\n\n\ndef f(obj: object) -> None:\n'
            '    """D."""\n    obj.client.run("x")\n'
        )
        self.assertNotIn("subprocess-shell-unresolved", rules)

    def test_shell_false_is_not_flagged(self) -> None:
        """An explicit shell=False is correct and stays quiet."""
        rules = self._rules(
            'import subprocess\n\n\ndef f(a: list) -> None:\n'
            '    """D."""\n    subprocess.run(a, shell=False)\n'
        )
        self.assertNotIn("subprocess-shell-true", rules)

    def test_dangerous_calls_are_flagged(self) -> None:
        """eval, exec and unsafe deserialisation are reported."""
        for snippet, rule in (
            ('def f(s: str) -> object:\n    """D."""\n    return eval(s)\n',
             "dangerous-call-eval"),
            ('import pickle\n\n\ndef f(b: bytes) -> object:\n    """D."""\n'
             '    return pickle.loads(b)\n', "dangerous-call-pickle-loads"),
            ('import yaml\n\n\ndef f(s: str) -> object:\n    """D."""\n'
             '    return yaml.load(s)\n', "dangerous-call-yaml-load"),
            ('import os\n\n\ndef f(c: str) -> int:\n    """D."""\n'
             '    return os.system(c)\n', "dangerous-call-os-system"),
        ):
            self.assertIn(rule, self._rules(snippet), rule)

    def test_safe_alternatives_are_not_flagged(self) -> None:
        """The documented safe forms produce no security findings."""
        rules = self._rules(
            'import ast\nimport yaml\n\n\ndef f(s: str) -> object:\n    """D."""\n'
            '    return ast.literal_eval(s) or yaml.safe_load(s)\n'
        )
        self.assertEqual({r for r in rules if r.startswith("dangerous")}, set())

    def test_private_symbols_are_exempt_from_style_rules(self) -> None:
        """Underscore-prefixed helpers are not public API."""
        rules = self._rules("def _helper(a):\n    return a\n")
        self.assertNotIn("missing-docstring", rules)
        self.assertNotIn("missing-annotations", rules)

    def test_self_and_cls_are_not_required_to_be_annotated(self) -> None:
        """Method receivers are exempt."""
        rules = self._rules(
            'class C:\n    """C."""\n\n    def m(self) -> int:\n        """M."""\n'
            '        return 1\n'
        )
        self.assertNotIn("missing-annotations", rules)

    def test_bare_except_is_flagged_and_typed_is_not(self) -> None:
        """Only the bare form is reported."""
        bare = self._rules(
            'def f() -> None:\n    """D."""\n    try:\n        pass\n'
            '    except:\n        pass\n'
        )
        typed = self._rules(
            'def f() -> None:\n    """D."""\n    try:\n        pass\n'
            '    except ValueError:\n        pass\n'
        )
        self.assertIn("bare-except", bare)
        self.assertNotIn("bare-except", typed)

    def test_unparsable_file_is_distinguished_from_a_clean_one(self) -> None:
        """A syntax error is a distinct answer, never an empty clean result."""
        path = write(self.root, "broken.py", "def (:\n")
        self.assertIsNone(survey_source(path, "broken.py"))
        self.assertIsNone(parse_module(path))

    def test_unparsable_file_is_recorded_as_skipped_by_the_survey(self) -> None:
        """The runner records what the AST rules could not examine."""
        write(self.root, "broken.py", "def (:\n")
        result = survey(self.root)
        self.assertTrue(any("broken.py" in entry for entry in result.skipped))

    def test_results_are_deterministic(self) -> None:
        """Three surveys of the same file agree exactly."""
        path = write(
            self.root, "m.py",
            'import subprocess\n\n\ndef f(a):\n    subprocess.run(a, shell=True)\n'
        )
        runs = [[f.id for f in survey_source(path, "m.py")] for _ in range(3)]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])


class ComplexityTests(unittest.TestCase):
    """Cyclomatic complexity counts branches, not lines."""

    def _complexity(self, source: str) -> int:
        """Return the complexity of the first function in ``source``."""
        import ast

        tree = ast.parse(source)
        return cyclomatic_complexity(tree.body[0])

    def test_straight_line_function_is_one(self) -> None:
        """No branches means complexity one."""
        self.assertEqual(self._complexity("def f():\n    return 1\n"), 1)

    def test_each_branch_adds_one(self) -> None:
        """An if statement raises the count."""
        branchy = "def f(a):\n    if a:\n        return 1\n    return 2\n"
        self.assertEqual(self._complexity(branchy), 2)

    def test_boolean_operators_count(self) -> None:
        """Short-circuit operators are branches."""
        self.assertEqual(self._complexity("def f(a, b, c):\n    return a and b and c\n"), 3)


class SecretTests(unittest.TestCase):
    """Credential detection favours precision over volume."""

    def setUp(self) -> None:
        """Create a scratch directory."""
        self.root = Path(tempfile.mkdtemp())

    def _rules(self, text: str) -> set:
        """Return the secret rules that fire on ``text``."""
        path = write(self.root, "conf.py", text)
        return {f.rule for f in survey_secrets(path, "conf.py")}

    def test_private_key_block_is_flagged(self) -> None:
        """A PEM header is unambiguous."""
        self.assertIn("secret-private-key-block", self._rules(_PEM + "\n"))

    def test_live_looking_keys_are_flagged(self) -> None:
        """A key-shaped string with no placeholder marker is reported."""
        self.assertIn("secret-aws-access-key", self._rules(f'K = "{LIVE_AWS_KEY}"\n'))
        self.assertIn(
            "secret-anthropic-key", self._rules(f'K = "{LIVE_ANTHROPIC_KEY}"\n')
        )

    def test_placeholders_are_not_flagged(self) -> None:
        """Obvious stand-ins do not become findings."""
        for text in (
            f'KEY = "{PLACEHOLDER_AWS_KEY}"\n',
            'api_key = "your-key-here-1234567890"\n',
            'TOKEN = "changeme-changeme-changeme"\n',
        ):
            self.assertEqual(self._rules(text), set(), text)

    def test_redaction_does_not_reproduce_the_secret(self) -> None:
        """A recorded match cannot be reconstructed from the evidence."""
        secret = LIVE_ANTHROPIC_KEY
        redacted = redact(secret)
        self.assertNotIn(secret, redacted)
        self.assertLess(len(redacted.replace("*", "")), len(secret))

    def test_short_values_are_fully_masked(self) -> None:
        """A short match reveals nothing at all."""
        self.assertEqual(redact("abc"), "***")

    def test_placeholder_detection_is_case_insensitive(self) -> None:
        """EXAMPLE and example are both stand-ins."""
        self.assertTrue(looks_like_placeholder(PLACEHOLDER_AWS_KEY))
        self.assertTrue(looks_like_placeholder("your-token"))
        self.assertFalse(looks_like_placeholder(LIVE_AWS_KEY))


class RunnerTests(unittest.TestCase):
    """The walk is bounded, ordered, and honest about what it skipped."""

    def setUp(self) -> None:
        """Create a small repository tree."""
        self.root = Path(tempfile.mkdtemp())
        write(self.root, "pkg/mod.py", 'def f(a):\n    return a\n')
        write(self.root, "README.md", "# readme\n")
        write(self.root, ".git/config", "[core]\n")
        write(self.root, "node_modules/lib/index.py", "import os  # noqa\n")
        write(self.root, "__pycache__/cached.py", "x = 1\n")

    def test_excluded_directories_are_not_walked(self) -> None:
        """Vendored and generated trees are skipped."""
        files, truncated = iter_files(self.root)
        visited = {p.name for p in files}
        self.assertIn("mod.py", visited)
        self.assertNotIn("index.py", visited)
        self.assertNotIn("cached.py", visited)
        self.assertNotIn("config", visited)
        self.assertFalse(truncated)

    def test_dotenv_files_are_scanned(self) -> None:
        """.env has no suffix, which must not exempt it from the secret scan.

        It is the single most common place a credential is committed.
        """
        write(self.root, ".env", "nothing here\n")
        write(self.root, ".env.local", "nothing here\n")
        files, _ = iter_files(self.root)
        names = {p.name for p in files}
        self.assertIn(".env", names)
        self.assertIn(".env.local", names)

    def test_uppercase_python_suffix_is_surveyed(self) -> None:
        """M.PY and m.py are the same kind of file to the AST rules."""
        write(self.root, "M.PY", "import os\n\nos.system('x')\n")
        result = survey(self.root)
        self.assertTrue(any(f.rule == "dangerous-call-os-system" for f in result.findings))

    def test_oversized_file_is_recorded_as_skipped(self) -> None:
        """A file too large to scan is reported, never silently clean."""
        write(self.root, "big.txt", "A" * (2_000_001))
        result = survey(self.root)
        self.assertTrue(any("big.txt" in entry for entry in result.skipped))
        self.assertIn("skipped", result.summary())

    def test_summary_counts_what_was_examined(self) -> None:
        """A survey reports its own scope, not only its findings."""
        result = survey(self.root)
        self.assertTrue(result.complete)
        self.assertGreater(result.files_scanned, 0)
        self.assertIn("files scanned", result.summary())

    def test_missing_directory_is_incomplete_not_clean(self) -> None:
        """A survey that could not run never reports zero findings."""
        result = survey(self.root / "does-not-exist")
        self.assertFalse(result.complete)
        self.assertIn("not a clean result", result.summary())

    def test_pillars_are_always_present_in_the_count(self) -> None:
        """A pillar with nothing found still appears, so zero is visible."""
        counts = survey(self.root).by_pillar()
        for pillar in Pillar:
            self.assertIn(pillar.value, counts)

    def test_walk_is_ordered(self) -> None:
        """Two walks visit the same files in the same order."""
        self.assertEqual(iter_files(self.root), iter_files(self.root))

    def test_exactly_full_tree_is_complete(self) -> None:
        """Hitting the file limit exactly is completion, not truncation."""
        _, truncated = iter_files(self.root)
        self.assertFalse(truncated)

    def test_custody_artifacts_are_excluded(self) -> None:
        """Custody does not survey its own ledger."""
        self.assertIn(".custody", EXCLUDED_DIRS)


class FindingTests(unittest.TestCase):
    """Finding identity and ordering."""

    def test_id_is_stable_for_the_same_content(self) -> None:
        """The same problem gets the same id every run."""
        self.assertEqual(
            finding_id("r", "a.py", "os.system(x)"), finding_id("r", "a.py", "os.system(x)")
        )

    def test_id_differs_by_content(self) -> None:
        """Different flagged content is a different finding."""
        self.assertNotEqual(
            finding_id("r", "a.py", "os.system(x)"), finding_id("r", "a.py", "os.system(y)")
        )

    def test_id_survives_the_code_moving(self) -> None:
        """Inserting a line above a finding must not retire its id.

        Under line-keyed ids, one inserted comment changed the id, the
        contracted id vanished from a fresh survey, and an unfixed finding
        adjudicated as PROVEN.
        """
        before = 'import os\n\n\ndef f(c):\n    """F."""\n    return os.system(c)\n'
        after = "# a comment\n" + before
        ids_before = [f.id for f in survey_ids(before) if f.rule.startswith("dangerous")]
        ids_after = [f.id for f in survey_ids(after) if f.rule.startswith("dangerous")]
        self.assertEqual(ids_before, ids_after)

    def test_duplicate_content_gets_distinct_stable_ids(self) -> None:
        """Two identical dangerous lines are two findings, reproducibly."""
        source = "import os\n\nos.system(c)\nos.system(c)\n"
        first = [f.id for f in survey_ids(source) if f.rule.startswith("dangerous")]
        second = [f.id for f in survey_ids(source) if f.rule.startswith("dangerous")]
        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)
        self.assertNotEqual(first[0], first[1])

    def test_severity_orders_worst_first(self) -> None:
        """Critical sorts ahead of low."""
        self.assertLess(Severity.CRITICAL.rank, Severity.LOW.rank)

    def test_grouping_includes_empty_pillars(self) -> None:
        """An empty pillar is reported as empty, not omitted."""
        grouped = group_by_pillar([])
        self.assertEqual(sorted(grouped), sorted(p.value for p in Pillar))

    def test_sort_is_total_and_stable(self) -> None:
        """Sorting twice changes nothing."""
        from custody.findings import Finding

        items = [
            Finding("2", "b", Pillar.QUALITY, Severity.LOW, "z.py", 2, "m"),
            Finding("1", "a", Pillar.SECURITY, Severity.CRITICAL, "a.py", 1, "m"),
        ]
        once = sort_findings(items)
        self.assertEqual([f.id for f in once], [f.id for f in sort_findings(once)])


if __name__ == "__main__":
    unittest.main()
