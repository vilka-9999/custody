"""Tests for proposal parsing, which never coerces a malformed contract."""

import unittest

from custody.findings import Finding, Pillar, Severity
from custody.remediator.agent import ProposalError, build_prompt, parse_proposal


def finding() -> Finding:
    """Return a finding to propose against."""
    return Finding(
        "CUS-1", "subprocess-shell-true", Pillar.SECURITY, Severity.CRITICAL,
        "app.py", 5, "shell=True", evidence="subprocess.run(cmd, shell=True)",
    )


class ParseTests(unittest.TestCase):
    """A proposal is accepted only when it is well formed."""

    def test_valid_payload_becomes_a_proposal(self) -> None:
        """A complete object yields a contract and file contents."""
        proposal = parse_proposal(
            {
                "allowed_paths": ["app.py"],
                "hypothesis": "pass a list",
                "verification": "tests pass",
                "files": {"app.py": "import subprocess\n"},
            },
            finding(), 0.02,
        )
        self.assertEqual(proposal.contract.allowed_paths, ["app.py"])
        self.assertEqual(proposal.measured_cost_usd, 0.02)

    def test_declared_cost_comes_from_measurement(self) -> None:
        """The model does not get to state its own spend."""
        proposal = parse_proposal(
            {"allowed_paths": ["a.py"], "files": {"a.py": "x = 1\n"}}, finding(), 0.03
        )
        self.assertEqual(proposal.declared_cost_usd, proposal.measured_cost_usd)

    def test_missing_files_is_rejected(self) -> None:
        """A contract with no change is not a proposal."""
        with self.assertRaises(ProposalError):
            parse_proposal({"allowed_paths": ["a.py"]}, finding(), 0.0)

    def test_missing_paths_is_rejected(self) -> None:
        """A change with no declared authority is refused."""
        with self.assertRaises(ProposalError):
            parse_proposal({"files": {"a.py": "x = 1\n"}}, finding(), 0.0)

    def test_wrong_types_are_rejected_not_coerced(self) -> None:
        """A malformed contract is never repaired into a valid one."""
        for payload in (
            {"allowed_paths": "a.py", "files": {"a.py": "x\n"}},
            {"allowed_paths": ["a.py"], "files": {"a.py": 42}},
            {"allowed_paths": [1], "files": {"a.py": "x\n"}},
            {"allowed_paths": ["a.py"], "files": []},
        ):
            with self.assertRaises(ProposalError):
                parse_proposal(payload, finding(), 0.0)

    def test_missing_hypothesis_is_recorded_as_absent(self) -> None:
        """A silent agent is recorded as silent, not as having no opinion."""
        proposal = parse_proposal(
            {"allowed_paths": ["a.py"], "files": {"a.py": "x = 1\n"}}, finding(), 0.0
        )
        self.assertIn("none given", proposal.contract.hypothesis)


class PromptTests(unittest.TestCase):
    """The prompt carries the evidence the agent needs."""

    def test_prompt_includes_location_and_evidence(self) -> None:
        """The agent is told exactly what was found and where."""
        prompt = build_prompt(__import__("pathlib").Path("."), finding())
        self.assertIn("app.py:5", prompt)
        self.assertIn("shell=True", prompt)


if __name__ == "__main__":
    unittest.main()
