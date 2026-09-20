"""Rule-based fixes that need no language model.

Some findings have exactly one correct repair, and asking a model to guess it
is both slower and less reliable than writing it down. Each fixer here is a
pure function from source text to source text, so its output is reproducible
and reviewable.

These are proposals like any other. They go through the same scope contract,
the same test gate, and the same adjudication as a model's work, and they are
reverted on the same terms. Nothing here is trusted because it is
deterministic; it is adjudicated because everything is.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Callable

from custody.findings import Finding
from custody.harness import Proposal
from custody.remediator.contract import ScopeContract, is_protected

SHELL_TRUE = re.compile(r",\s*shell\s*=\s*True")


def _lines(source: str) -> list[str]:
    """Split source into lines, preserving the ability to rejoin exactly."""
    return source.split("\n")


def _indent_of(line: str) -> str:
    """Return the leading whitespace of ``line``."""
    return line[: len(line) - len(line.lstrip())]


def fix_shell_true(source: str, finding: Finding) -> str | None:
    """Remove ``shell=True`` from a subprocess call.

    Dropping the keyword makes the call pass its argument list directly to the
    operating system, which is the documented safe form. It is only applied
    when the first argument is already a list or a name, because rewriting a
    command *string* into a list is a semantic change this fixer will not
    guess at.
    """
    lines = _lines(source)
    index = finding.line - 1
    if not 0 <= index < len(lines):
        return None
    line = lines[index]
    if "shell" not in line or not SHELL_TRUE.search(line):
        return None
    if re.search(r"\(\s*['\"]", line):
        return None
    lines[index] = SHELL_TRUE.sub("", line)
    return "\n".join(lines)


def fix_bare_except(source: str, finding: Finding) -> str | None:
    """Narrow a bare ``except:`` to ``except Exception:``.

    This preserves the handler's intent while letting KeyboardInterrupt and
    SystemExit propagate, which is the behaviour almost every bare handler
    actually wanted.
    """
    lines = _lines(source)
    index = finding.line - 1
    if not 0 <= index < len(lines):
        return None
    stripped = lines[index].strip()
    if stripped != "except:":
        return None
    lines[index] = f"{_indent_of(lines[index])}except Exception:"
    return "\n".join(lines)


def _docstring_for(node: ast.AST, name: str) -> str:
    """Compose a minimal, accurate docstring for a node with none."""
    if isinstance(node, ast.ClassDef):
        return f'"""{name}."""'
    returns = getattr(node, "returns", None)
    if returns is not None and not (
        isinstance(returns, ast.Constant) and returns.value is None
    ):
        return f'"""Return the result of {name}."""'
    return f'"""Perform {name}."""'


def fix_missing_docstring(source: str, finding: Finding) -> str | None:
    """Insert a minimal docstring on a public function or class.

    A generated docstring is a weak fix and it is worth being honest about
    that: it satisfies the rule without adding knowledge. It is included
    because the alternative - leaving public API undocumented - is worse, and
    because the auditor will still confirm the finding actually cleared.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    target = None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.lineno == finding.line
            and not ast.get_docstring(node)
        ):
            target = node
            break
    if target is None:
        return None

    lines = _lines(source)
    body_start = target.body[0].lineno - 1
    if not 0 <= body_start < len(lines):
        return None
    indent = _indent_of(lines[body_start])
    lines.insert(body_start, indent + _docstring_for(target, target.name))
    return "\n".join(lines)


FIXERS: dict[str, Callable[[str, Finding], str | None]] = {
    "subprocess-shell-true": fix_shell_true,
    "bare-except": fix_bare_except,
    "missing-docstring": fix_missing_docstring,
}

HYPOTHESES: dict[str, str] = {
    "subprocess-shell-true": "drop shell=True so the argument list goes straight to the OS",
    "bare-except": "narrow the handler to Exception so control-flow signals propagate",
    "missing-docstring": "add a minimal docstring to the undocumented public symbol",
}


def can_fix(finding: Finding) -> bool:
    """Return whether this finding is one a deterministic fixer may address.

    A finding inside protected territory - a test, CI configuration, a quality
    threshold - is never fixable here, however simple the repair looks. The
    harness would refuse the contract anyway; declining up front keeps a
    predictable refusal out of the verdict column, where it would read as the
    agent having attempted something.
    """
    return finding.rule in FIXERS and not is_protected(finding.path)


def propose(repo: Path, finding: Finding) -> Proposal | None:
    """Build a proposal for ``finding``, or ``None`` when no fixer applies.

    Returning ``None`` is a real answer: it means this remediator declines to
    guess, which is preferable to a change that clears a rule without fixing
    the problem.
    """
    if not can_fix(finding):
        return None
    fixer = FIXERS[finding.rule]
    try:
        source = (repo / finding.path).read_text(encoding="utf-8")
    except OSError:
        return None

    updated = fixer(source, finding)
    if updated is None or updated == source:
        return None

    try:
        ast.parse(updated)
    except SyntaxError:
        return None

    return Proposal(
        contract=ScopeContract(
            finding_id=finding.id,
            allowed_paths=[finding.path],
            hypothesis=HYPOTHESES.get(finding.rule, "apply the deterministic fix"),
            verification="the suite stays green and a fresh survey no longer reports it",
        ),
        files={finding.path: updated},
        declared_cost_usd=0.0,
        measured_cost_usd=0.0,
        notes={"remediator": "deterministic", "rule": finding.rule},
    )
