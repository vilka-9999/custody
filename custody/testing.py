"""Run a project's own test suite and report the result as evidence.

Custody never decides for itself whether a change is safe. It asks the
project's own suite and records the answer. Two failure modes are treated as
distinct throughout: a suite that ran and failed, and a suite that could not
be run at all. The second is never reported as the first, and never as a pass.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

DEFAULT_TIMEOUT = 600
"""Seconds a test suite may run before it is killed."""

MAX_CAPTURED_OUTPUT = 20000
"""Characters of transcript retained; enough to diagnose, bounded for the ledger."""


@dataclass(frozen=True)
class TestOutcome:
    """The result of one attempt to run a project's tests.

    Attributes:
        ran: Whether the suite executed at all.
        passed: Whether it executed and reported success.
        command: The argument list that was invoked.
        returncode: Process exit status, or -1 when it never started.
        output: Captured stdout and stderr, truncated.
        reason: Why the suite could not run, when ``ran`` is False.
    """

    ran: bool
    passed: bool
    command: List[str]
    returncode: int = -1
    output: str = ""
    reason: str = ""

    def summary(self) -> str:
        """Return a one-line summary that never overstates the result."""
        if not self.ran:
            return "test suite did not run (%s) - this is not a pass" % (self.reason or "unknown")
        return "test suite %s (exit %d)" % ("passed" if self.passed else "FAILED", self.returncode)

    def to_dict(self) -> dict:
        """Return a JSON-serialisable view for the ledger."""
        return {
            "ran": self.ran,
            "passed": self.passed,
            "command": list(self.command),
            "returncode": self.returncode,
            "reason": self.reason,
            "output_tail": self.output[-2000:],
        }


def detect_command(repo: Path) -> Optional[List[str]]:
    """Choose how to run this project's tests, or return ``None``.

    Preference order is deliberate: an explicit pytest layout wins, then a
    stdlib unittest discovery, because unittest works with no dependencies at
    all and is therefore the safer fallback.
    """
    tests_dir = repo / "tests"
    has_tests = tests_dir.is_dir() or any(repo.glob("test_*.py"))
    if not has_tests:
        return None

    if shutil.which("pytest") and (repo / "pytest.ini").exists():
        return ["pytest", "-q"]

    config_mentions_pytest = any(
        (repo / name).exists() and "pytest" in (repo / name).read_text(
            encoding="utf-8", errors="replace"
        )
        for name in ("pyproject.toml", "setup.cfg", "tox.ini")
    )
    if config_mentions_pytest and shutil.which("pytest"):
        return ["pytest", "-q"]

    return [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"]


def run_tests(
    repo: Path,
    command: Optional[Sequence[str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> TestOutcome:
    """Run the project's tests inside ``repo`` and capture the outcome."""
    repo = Path(repo)
    chosen = list(command) if command else detect_command(repo)
    if chosen is None:
        return TestOutcome(
            ran=False, passed=False, command=[],
            reason="no test suite was found in this repository",
        )

    try:
        completed = subprocess.run(
            chosen,
            cwd=str(repo),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return TestOutcome(
            ran=False, passed=False, command=chosen,
            reason="test runner %r is not installed" % chosen[0],
        )
    except subprocess.TimeoutExpired:
        return TestOutcome(
            ran=False, passed=False, command=chosen,
            reason="test suite exceeded %ss and was killed" % timeout,
        )
    except OSError as exc:
        return TestOutcome(
            ran=False, passed=False, command=chosen, reason="could not start runner: %s" % exc
        )

    output = (completed.stdout + completed.stderr)[-MAX_CAPTURED_OUTPUT:]
    return TestOutcome(
        ran=True,
        passed=completed.returncode == 0,
        command=chosen,
        returncode=completed.returncode,
        output=output,
    )
