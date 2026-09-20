"""Abstract-syntax-tree rules over Python source.

Each rule is a pure function of one parsed module. Rules never read anything
outside the file they are given, so a finding can always be reproduced from
the file alone.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Callable

from custody.findings import Finding, Pillar, Severity, anchor_ids, sort_findings

DANGEROUS_CALLS = {
    "eval": (Severity.CRITICAL, "eval() executes arbitrary code"),
    "exec": (Severity.CRITICAL, "exec() executes arbitrary code"),
    "compile": (Severity.HIGH, "compile() builds executable code at runtime"),
}

DANGEROUS_ATTRIBUTES = {
    ("pickle", "loads"): (Severity.CRITICAL, "pickle.loads() deserialises arbitrary objects"),
    ("pickle", "load"): (Severity.CRITICAL, "pickle.load() deserialises arbitrary objects"),
    ("yaml", "load"): (Severity.HIGH, "yaml.load() without SafeLoader executes tags"),
    ("os", "system"): (Severity.HIGH, "os.system() passes a string to a shell"),
    ("marshal", "loads"): (Severity.HIGH, "marshal.loads() is unsafe on untrusted input"),
}

SUBPROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)
"""Calls whose ``shell`` keyword decides whether a shell interprets the command.

The shell rules apply only to these. An earlier version inspected every call
that spread keyword arguments, which flagged ordinary constructor calls like
``DiffContext(**base)`` seventeen times in this repository alone. A detector
that fires on everything tells you nothing.
"""

MAX_COMPLEXITY = 10
"""Cyclomatic complexity above which a function is reported."""

_BRANCHING_NODES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.ExceptHandler,
    ast.With,
    ast.AsyncWith,
    ast.Assert,
    ast.IfExp,
)


def parse_module(path: Path) -> ast.Module | None:
    """Parse ``path`` as Python, returning ``None`` when it will not parse.

    Only parse failures return ``None``. An unreadable file raises ``OSError``
    to the caller: a file that could not be read must be recorded as skipped,
    never silently reported as clean.
    """
    try:
        return ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (SyntaxError, ValueError):
        return None


def _excerpt(path: Path, line: int) -> str:
    """Return the stripped source line at ``line``, or an empty string."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def import_aliases(tree: ast.Module) -> dict[str, str]:
    """Map local names to the dotted names they were imported from.

    ``import os as o`` maps ``o`` to ``os``; ``from os import system as run``
    maps ``run`` to ``os.system``. Without this, renaming an import hides a
    dangerous call from every rule below - and a remediator could "fix" a
    finding by aliasing the import rather than removing the call, which the
    auditor would then see as legitimately resolved.

    Only module-level and nested import statements are tracked. Dynamic
    rebinding (``f = os.system``) is not resolved, and is a known gap.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{node.module}.{alias.name}"
    return aliases


def _resolve(name: str, aliases: dict[str, str]) -> str:
    """Return ``name`` with its leading segment expanded through ``aliases``."""
    if not name:
        return name
    head, _, rest = name.partition(".")
    target = aliases.get(head)
    if target is None:
        return name
    return f"{target}.{rest}" if rest else target


def _call_name(node: ast.Call) -> str:
    """Return the full dotted name for a call target, e.g. ``os.system``.

    The whole attribute chain is kept. An earlier version collapsed a deep
    chain to its final attribute, so with ``from subprocess import run``
    imported, an unrelated ``obj.client.run(...)`` resolved to
    ``subprocess.run`` and produced a false positive. A chain whose base is
    not a name (a call result, a subscript) has no static identity and
    returns empty.
    """
    parts: list[str] = []
    func: ast.expr = node.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))
    return ""


def rule_shell_true(tree: ast.Module, rel: str, path: Path) -> list[Finding]:
    """Report subprocess calls that may hand a command to a shell.

    A literal ``shell=True`` is reported outright. A non-literal value -
    ``shell=flag``, or a ``**kwargs`` spread that could carry one - is
    reported at lower severity rather than ignored: the rule cannot prove a
    shell is involved, and saying nothing would be indistinguishable from
    having checked and found it safe.
    """
    found: list[Finding] = []
    aliases = import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _resolve(_call_name(node), aliases) not in SUBPROCESS_CALLS:
            continue
        for keyword in node.keywords:
            if keyword.arg is None:
                found.extend(_spread_shell_finding(keyword.value, rel, node.lineno, path))
                continue
            if keyword.arg != "shell":
                continue
            found.extend(_shell_value_finding(keyword.value, rel, node.lineno, path))
    return found


def _shell_value_finding(value: ast.expr, rel: str, line: int, path: Path) -> list[Finding]:
    """Classify one ``shell=`` value into a finding, or none for a falsy literal.

    Any truthy constant is reported at full severity, not only the literal
    ``True``: ``shell=1`` hands the command to a shell exactly as
    ``shell=True`` does, and an earlier version that keyed on ``is True``
    reported nothing for it - a one-character bypass of the rule.
    """
    if isinstance(value, ast.Constant):
        if not value.value:
            return []
        return [
            _shell_finding(
                rel, line, path, "subprocess-shell-true", Severity.CRITICAL,
                "Subprocess call sets shell to a truthy value; pass an "
                "argument list instead.",
            )
        ]
    return [
        _shell_finding(
            rel, line, path, "subprocess-shell-unresolved", Severity.MEDIUM,
            "Subprocess call sets shell to a non-literal value; "
            "whether a shell runs cannot be determined here.",
        )
    ]


def _spread_shell_finding(value: ast.expr, rel: str, line: int, path: Path) -> list[Finding]:
    """Classify a ``**`` spread that may carry a ``shell`` keyword.

    A literal dict is read directly: a constant truthy ``shell`` value is the
    real thing and reported at full severity rather than hedged, a constant
    falsy one is safe, and anything else - including a non-literal dict -
    cannot be ruled out and is reported as unresolved.
    """
    if isinstance(value, ast.Dict):
        for key, item in zip(value.keys, value.values):
            if isinstance(key, ast.Constant) and key.value == "shell":
                return _shell_value_finding(item, rel, line, path)
        return []
    return [
        _shell_finding(
            rel, line, path, "subprocess-shell-unresolved", Severity.MEDIUM,
            "Subprocess call spreads keyword arguments; a shell "
            "cannot be ruled out here.",
        )
    ]


def _shell_finding(
    rel: str, line: int, path: Path, rule: str, severity: Severity, message: str
) -> Finding:
    """Build one shell-related finding; its id is assigned by the anchor pass."""
    return Finding(
        id="",
        rule=rule,
        pillar=Pillar.SECURITY,
        severity=severity,
        path=rel,
        line=line,
        message=message,
        evidence=_excerpt(path, line),
    )


def rule_dangerous_calls(tree: ast.Module, rel: str, path: Path) -> list[Finding]:
    """Report calls to builtins and stdlib functions that execute input.

    Call targets are resolved through the module's import aliases first, so
    ``import os as o; o.system(x)`` is reported exactly like ``os.system(x)``.
    """
    found: list[Finding] = []
    aliases = import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        raw = _call_name(node)
        name = _resolve(raw, aliases)
        severity_message = DANGEROUS_CALLS.get(name) or DANGEROUS_CALLS.get(raw)
        if severity_message is None and "." in name:
            module, _, attr = name.rpartition(".")
            severity_message = DANGEROUS_ATTRIBUTES.get((module.split(".")[-1], attr))
        if severity_message is None:
            continue
        severity, message = severity_message
        found.append(
            Finding(
                id="",
                rule=f"dangerous-call-{name.replace('.', '-')}",
                pillar=Pillar.SECURITY,
                severity=severity,
                path=rel,
                line=node.lineno,
                message=message,
                evidence=_excerpt(path, node.lineno),
            )
        )
    return found


def _is_public(name: str) -> bool:
    """Return whether ``name`` is part of a module's public surface."""
    return not name.startswith("_")


def rule_missing_annotations(tree: ast.Module, rel: str, path: Path) -> list[Finding]:
    """Report public functions whose signature or return type is untyped."""
    found: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_public(node.name):
            continue
        args = list(node.args.args) + list(node.args.kwonlyargs)
        untyped = [a.arg for a in args if a.annotation is None and a.arg not in ("self", "cls")]
        if node.returns is None:
            untyped.append("->")
        if not untyped:
            continue
        found.append(
            Finding(
                id="",
                rule="missing-annotations",
                pillar=Pillar.QUALITY,
                severity=Severity.LOW,
                path=rel,
                line=node.lineno,
                message=f"Public function {node.name}() is missing type annotations.",
                evidence=_excerpt(path, node.lineno),
                detail={"untyped": sorted(untyped), "function": node.name},
            )
        )
    return found


def rule_missing_docstring(tree: ast.Module, rel: str, path: Path) -> list[Finding]:
    """Report public functions and classes with no docstring."""
    found: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if not _is_public(node.name) or ast.get_docstring(node):
            continue
        found.append(
            Finding(
                id="",
                rule="missing-docstring",
                pillar=Pillar.QUALITY,
                severity=Severity.LOW,
                path=rel,
                line=node.lineno,
                message=f"Public {type(node).__name__.replace('Def', '').lower()} "
                f"{node.name} has no docstring.",
                evidence=_excerpt(path, node.lineno),
                detail={"symbol": node.name},
            )
        )
    return found


def cyclomatic_complexity(node: ast.AST) -> int:
    """Return an approximate cyclomatic complexity for a function node."""
    score = 1
    for child in ast.walk(node):
        if isinstance(child, _BRANCHING_NODES):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += len(child.values) - 1
    return score


def rule_complexity(tree: ast.Module, rel: str, path: Path) -> list[Finding]:
    """Report functions whose branching exceeds :data:`MAX_COMPLEXITY`."""
    found: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        score = cyclomatic_complexity(node)
        if score <= MAX_COMPLEXITY:
            continue
        found.append(
            Finding(
                id="",
                rule="high-complexity",
                pillar=Pillar.QUALITY,
                severity=Severity.MEDIUM,
                path=rel,
                line=node.lineno,
                message=f"{node.name}() has cyclomatic complexity {score} "
                f"(limit {MAX_COMPLEXITY}).",
                evidence=_excerpt(path, node.lineno),
                detail={"complexity": score, "limit": MAX_COMPLEXITY, "function": node.name},
            )
        )
    return found


def rule_bare_except(tree: ast.Module, rel: str, path: Path) -> list[Finding]:
    """Report bare ``except:`` handlers, which swallow control-flow exceptions."""
    found: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            found.append(
                Finding(
                    id="",
                    rule="bare-except",
                    pillar=Pillar.QUALITY,
                    severity=Severity.MEDIUM,
                    path=rel,
                    line=node.lineno,
                    message="Bare except: also catches KeyboardInterrupt and SystemExit.",
                    evidence=_excerpt(path, node.lineno),
                )
            )
    return found


RULES: list[Callable[[ast.Module, str, Path], list[Finding]]] = [
    rule_shell_true,
    rule_dangerous_calls,
    rule_missing_annotations,
    rule_missing_docstring,
    rule_complexity,
    rule_bare_except,
]


def survey_source(path: Path, rel: str) -> list[Finding] | None:
    """Run every AST rule against one Python file.

    Returns ``None`` when the file does not parse as Python. That is a
    distinct answer from an empty list: a file the rules could not examine
    must be recorded as skipped by the caller, never counted as clean.
    """
    tree = parse_module(path)
    if tree is None:
        return None
    found: list[Finding] = []
    for rule in RULES:
        found.extend(rule(tree, rel, path))
    return sort_findings(anchor_ids(found))
