"""The scope contract: authority a remediation attempt declares before acting.

The contract exists so that overreach is detectable rather than arguable. An
attempt names the files it may write *before* it writes any of them, and the
harness compares that declaration against what actually changed on disk. A
declaration is not a promise the agent keeps; it is a boundary the harness
enforces.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence

PROTECTED_GLOBS: List[str] = [
    "tests/*",
    "tests/**",
    "**/test_*.py",
    "**/*_test.py",
    ".github/*",
    ".github/**",
    "pyproject.toml",
    "setup.cfg",
    "tox.ini",
    ".custody/*",
    ".custody/**",
    "custody/auditor/*",
    "custody/auditor/**",
    "custody/ledger.py",
]
"""Paths no remediation attempt may write, whatever it declares.

Tests and CI configuration are protected because the cheapest way to make a
failing gate pass is to weaken the gate. The auditor's own source and the
ledger are protected because an agent that can edit its judge or its record is
not being audited at all.
"""

MAX_DECLARED_PATHS = 20
"""An attempt that needs more files than this is too broad to adjudicate."""


class ScopeViolation(Exception):
    """Raised when an attempt declares or touches forbidden territory."""


@dataclass(frozen=True)
class ScopeContract:
    """Authority claimed by one remediation attempt.

    Attributes:
        finding_id: The single finding this attempt is permitted to address.
        allowed_paths: Repository-relative paths the attempt may write.
        hypothesis: What the agent believes will fix the finding.
        verification: How the agent expects the fix to be confirmed.
        base_sha: Commit the attempt starts from, used for auto-revert.
    """

    finding_id: str
    allowed_paths: List[str]
    hypothesis: str
    verification: str
    base_sha: str = ""
    notes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable view for the ledger."""
        return {
            "finding_id": self.finding_id,
            "allowed_paths": sorted(self.allowed_paths),
            "hypothesis": self.hypothesis,
            "verification": self.verification,
            "base_sha": self.base_sha,
            "notes": dict(self.notes),
        }


def is_protected(path: str, protected: Sequence[str] = tuple(PROTECTED_GLOBS)) -> bool:
    """Return whether ``path`` falls under any protected glob."""
    normalised = path.replace("\\", "/")
    while normalised.startswith("./"):
        normalised = normalised[2:]
    for pattern in protected:
        if fnmatch.fnmatch(normalised, pattern):
            return True
        if pattern.endswith("/**") and normalised.startswith(pattern[:-2]):
            return True
        if pattern.startswith("**/") and normalised.endswith(pattern[2:]):
            return True
    return False


def validate_contract(
    contract: ScopeContract, protected: Sequence[str] = tuple(PROTECTED_GLOBS)
) -> None:
    """Reject a contract that claims authority it may not have.

    Raises:
        ScopeViolation: If the contract is empty, over-broad, or names a
            protected path. Rejection happens before the agent runs, so a
            forbidden declaration costs nothing but a ledger entry.
    """
    if not contract.finding_id:
        raise ScopeViolation("contract names no finding")
    if not contract.allowed_paths:
        raise ScopeViolation("contract declares no writable paths")
    if len(contract.allowed_paths) > MAX_DECLARED_PATHS:
        raise ScopeViolation(
            "contract declares %d paths (limit %d)"
            % (len(contract.allowed_paths), MAX_DECLARED_PATHS)
        )
    for path in contract.allowed_paths:
        if path.startswith("/") or ".." in path:
            raise ScopeViolation("path escapes the repository: %s" % path)
        if is_protected(path, protected):
            raise ScopeViolation("path is protected and may not be declared: %s" % path)


def check_scope(
    contract: ScopeContract,
    changed: Iterable[str],
    protected: Sequence[str] = tuple(PROTECTED_GLOBS),
) -> List[str]:
    """Return the paths that were written without authority.

    A path is a violation when it is protected, or when it does not match any
    glob the contract declared. The result is deliberately a list rather than
    a boolean so the ledger can record exactly what escaped.
    """
    escaped: List[str] = []
    for path in sorted(set(changed)):
        if is_protected(path, protected):
            escaped.append(path)
            continue
        permitted = any(
            fnmatch.fnmatch(path, pattern) or path == pattern
            for pattern in contract.allowed_paths
        )
        if not permitted:
            escaped.append(path)
    return escaped
