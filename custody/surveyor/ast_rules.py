"""Abstract-syntax-tree rules over Python source.

Each rule is a pure function of one parsed module. Rules never read anything
outside the file they are given, so a finding can always be reproduced from
the file alone.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Callable, Dict, List, Optional

from custody.findings import Finding, Pillar, Severity, finding_id, sort_findings

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


def parse_module(path: Path) -> Optional[ast.Module]:
    """Parse ``path`` as Python, returning ``None`` when it will not parse."""
    try:
        return ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (SyntaxError, ValueError, OSError):
        return None


def _excerpt(path: Path, line: int) -> str:
    """Return the stripped source line at ``line``, or an empty string."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def import_aliases(tree: ast.Module) -> Dict[str, str]:
    """Map local names to the dotted names they were imported from.

    ``import os as o`` maps ``o`` to ``os``; ``from os import system as run``
    maps ``run`` to ``os.system``. Without this, renaming an import hides a
    dangerous call from every rule below - and a remediator could "fix" a
    finding by aliasing the import rather than removing the call, which the
    auditor would then see as legitimately resolved.

    Only module-level and nested import statements are tracked. Dynamic
    rebinding (``f = os.system``) is not resolved, and is a known gap.
    """
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = "%s.%s" % (node.module, alias.name)
    return aliases


def _resolve(name: str, aliases: Dict[str, str]) -> str:
    """Return ``name`` with its leading segment expanded through ``aliases``."""
    if not name:
        return name
    head, _, rest = name.partition(".")
    target = aliases.get(head)
    if target is None:
        return name
    return "%s.%s" % (target, rest) if rest else target


def _call_name(node: ast.Call) -> str:
    """Return a dotted name for a call target, e.g. ``os.system``."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def rule_shell_true(tree: ast.Module, rel: str, path: Path) -> List[Finding]:
    """Report subprocess calls that may hand a command to a shell.

    A literal ``shell=True`` is reported outright. A non-literal value -
    ``shell=flag``, or a ``**kwargs`` spread that could carry one - is
    reported at lower severity rather than ignored: the rule cannot prove a
    shell is involved, and saying nothing would be indistinguishable from
    having checked and found it safe.
    """
    found: List[Finding] = []
    aliases = import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _resolve(_call_name(node), aliases) not in SUBPROCESS_CALLS:
            continue
        for keyword in node.keywords:
            if keyword.arg is None:
                if _spread_may_carry_shell(keyword.value):
                    found.append(
                        _shell_finding(
                            rel, node.lineno, path, "subprocess-shell-unresolved",
                            Severity.MEDIUM,
                            "Subprocess call spreads keyword arguments; a shell "
                            "cannot be ruled out here.",
                        )
                    )
                continue
            if keyword.arg != "shell":
                continue
            value = keyword.value
            if isinstance(value, ast.Constant):
                if value.value is True:
                    found.append(
                        _shell_finding(
                            rel, node.lineno, path, "subprocess-shell-true",
                            Severity.CRITICAL,
                            "Subprocess call uses shell=True; pass an argument "
                            "list instead.",
                        )
                    )
            else:
                found.append(
                    _shell_finding(
                        rel, node.lineno, path, "subprocess-shell-unresolved",
                        Severity.MEDIUM,
                        "Subprocess call sets shell to a non-literal value; "
                        "whether a shell runs cannot be determined here.",
                    )
                )
    return found


def _shell_finding(
    rel: str, line: int, path: Path, rule: str, severity: Severity, message: str
) -> Finding:
    """Build one shell-related finding."""
    return Finding(
        id=finding_id(rule, rel, line),
        rule=rule,
        pillar=Pillar.SECURITY,
        severity=severity,
        path=rel,
        line=line,
        message=message,
        evidence=_excerpt(path, line),
    )


def _spread_may_carry_shell(value: ast.AST) -> bool:
    """Return whether a ``**`` spread could introduce a shell keyword.

    A literal dict is inspected directly; anything else is unknowable from
    the syntax tree alone and is treated as possible.
    """
    if isinstance(value, ast.Dict):
        for key in value.keys:
            if isinstance(key, ast.Constant) and key.value == "shell":
                return True
        return False
    return True


def rule_dangerous_calls(tree: ast.Module, rel: str, path: Path) -> List[Finding]:
    """Report calls to builtins and stdlib functions that execute input.

    Call targets are resolved through the module's import aliases first, so
    ``import os as o; o.system(x)`` is reported exactly like ``os.system(x)``.
    """
    found: List[Finding] = []
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
                id=finding_id(f"dangerous-call-{name}", rel, node.lineno),
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


def rule_missing_annotations(tree: ast.Module, rel: str, path: Path) -> List[Finding]:
    """Report public functions whose signature or return type is untyped."""
    found: List[Finding] = []
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
                id=finding_id("missing-annotations", rel, node.lineno),
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


def rule_missing_docstring(tree: ast.Module, rel: str, path: Path) -> List[Finding]:
    """Report public functions and classes with no docstring."""
    found: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if not _is_public(node.name) or ast.get_docstring(node):
            continue
        found.append(
            Finding(
                id=finding_id("missing-docstring", rel, node.lineno),
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


def rule_complexity(tree: ast.Module, rel: str, path: Path) -> List[Finding]:
    """Report functions whose branching exceeds :data:`MAX_COMPLEXITY`."""
    found: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        score = cyclomatic_complexity(node)
        if score <= MAX_COMPLEXITY:
            continue
        found.append(
            Finding(
                id=finding_id("high-complexity", rel, node.lineno),
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


def rule_bare_except(tree: ast.Module, rel: str, path: Path) -> List[Finding]:
    """Report bare ``except:`` handlers, which swallow control-flow exceptions."""
    found: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            found.append(
                Finding(
                    id=finding_id("bare-except", rel, node.lineno),
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


RULES: List[Callable[[ast.Module, str, Path], List[Finding]]] = [
    rule_shell_true,
    rule_dangerous_calls,
    rule_missing_annotations,
    rule_missing_docstring,
    rule_complexity,
    rule_bare_except,
]


def survey_source(path: Path, rel: str) -> List[Finding]:
    """Run every AST rule against one Python file."""
    tree = parse_module(path)
    if tree is None:
        return []
    found: List[Finding] = []
    for rule in RULES:
        found.extend(rule(tree, rel, path))
    return sort_findings(found)
