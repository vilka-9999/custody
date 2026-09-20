"""The scope contract: authority a remediation attempt declares before acting.

The contract exists so that overreach is detectable rather than arguable. An
attempt names the files it may write *before* it writes any of them, and the
harness compares that declaration against what actually changed on disk. A
declaration is not a promise the agent keeps; it is a boundary the harness
enforces.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath

GLOB_CHARS = frozenset("*?[")
"""Characters that make a declared path a pattern rather than a name."""

PROTECTED_GLOBS: list[str] = [
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

INTEGRITY_GLOBS: list[str] = [
    ".custody/*",
    ".custody/**",
    "custody/auditor/*",
    "custody/auditor/**",
    "custody/surveyor/*",
    "custody/surveyor/**",
    "custody/ledger.py",
    "custody/harness.py",
    "custody/gitio.py",
    "custody/testing.py",
    "custody/llm.py",
    "custody/findings.py",
    "custody/remediator/contract.py",
]
"""Paths a remediator is *prevented* from writing, not merely caught writing.

The rest of :data:`PROTECTED_GLOBS` is enforced by detection: the agent is
allowed to write a test file and is then caught and reverted, which is what
makes the audit meaningful. These paths are different. An agent that can edit
the ledger or the auditor can corrupt the evidence of its own conduct, so the
write itself is refused rather than adjudicated afterwards.

The boundary covers the whole enforcement and evidence core, not only the
auditor: the harness (which enforces this list), the git and test runners
(which produce the evidence), the surveyor (whose fresh run decides whether
a finding cleared), the cost accounting, and this module. An earlier version
protected only the auditor and the ledger, so in a self-audit an agent could
legally rewrite the guard that was supposed to constrain it - the edit took
effect on the next run, checked in under a green suite. The remediators
themselves, the CLI, and the read-only console stay writable: none of them
decides a verdict or records the evidence one rests on.
"""


def is_integrity_critical(path: str) -> bool:
    """Return whether ``path`` may never be written, even to catch the attempt."""
    return is_protected(path, tuple(INTEGRITY_GLOBS))


MAX_DECLARED_PATHS = 20
"""An attempt that needs more files than this is too broad to adjudicate."""


class ScopeViolationError(Exception):
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
    allowed_paths: list[str]
    hypothesis: str
    verification: str
    base_sha: str = ""
    notes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view for the ledger."""
        return {
            "finding_id": self.finding_id,
            "allowed_paths": sorted(self.allowed_paths),
            "hypothesis": self.hypothesis,
            "verification": self.verification,
            "base_sha": self.base_sha,
            "notes": dict(self.notes),
        }


def is_repo_relative(path: str) -> bool:
    """Return whether ``path`` is a plain path inside a repository.

    Rejects absolute paths, Windows drive letters, and any ``..`` segment.
    A path containing ``..`` may still land inside the repository once
    resolved, so this is a syntactic filter applied before resolution, not a
    substitute for it.
    """
    candidate = path.replace("\\", "/")
    if not candidate or candidate.startswith("/") or candidate.startswith("~"):
        return False
    if ":" in candidate:
        # A colon anywhere is refused, not only at a drive-letter position:
        # on NTFS, "custody/ledger.py:stream" names an alternate data stream
        # attached to the protected file, and no repository-relative path a
        # remediator legitimately writes contains one.
        return False
    return ".." not in PurePosixPath(candidate).parts


def normalise(path: str) -> str:
    """Return ``path`` in the form protection globs are matched against.

    Separators are unified, ``./`` prefixes dropped, and the result lowercased.
    Case folding matters because most desktop filesystems are case-insensitive:
    on them ``CUSTODY/LEDGER.PY`` and ``custody/ledger.py`` are the same file,
    and a case-sensitive glob would refuse one while permitting the other.

    This can only over-match, never under-match. Refusing a write that was
    actually harmless costs an attempt; permitting one that was not costs the
    integrity of the audit.
    """
    normalised = path.replace("\\", "/")
    while normalised.startswith("./"):
        normalised = normalised[2:]
    return normalised.lower()


def is_protected(path: str, protected: Sequence[str] = tuple(PROTECTED_GLOBS)) -> bool:
    """Return whether ``path`` falls under any protected glob.

    ``path`` must already be repository-relative and free of ``..`` segments.
    Callers handling untrusted input resolve the path against the repository
    root first - matching a glob against an unresolved string is how a
    traversal that cancels back onto a protected file slips through.
    """
    normalised = normalise(path)
    for raw in protected:
        pattern = normalise(raw)
        if fnmatch.fnmatchcase(normalised, pattern):
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

    Declared paths must be concrete file names, never patterns. A contract
    that declares ``**`` has named nothing and claimed everything: the
    declared string matches no protected glob, yet every write it later makes
    falls inside it, so scope-escape can never fire. "Names the files it may
    write in advance" means names, not shapes.

    Raises:
        ScopeViolationError: If the contract is empty, over-broad, names a
            protected path, or declares a wildcard. Rejection happens before
            the agent runs, so a forbidden declaration costs nothing but a
            ledger entry.
    """
    if not contract.finding_id:
        raise ScopeViolationError("contract names no finding")
    if not contract.allowed_paths:
        raise ScopeViolationError("contract declares no writable paths")
    if len(contract.allowed_paths) > MAX_DECLARED_PATHS:
        raise ScopeViolationError(
            "contract declares %d paths (limit %d)"
            % (len(contract.allowed_paths), MAX_DECLARED_PATHS)
        )
    for path in contract.allowed_paths:
        if any(char in GLOB_CHARS for char in path):
            raise ScopeViolationError(f"declared path is a pattern, not a file: {path}")
        if not is_repo_relative(path):
            raise ScopeViolationError(f"path escapes the repository: {path}")
        if is_protected(path, protected):
            raise ScopeViolationError(f"path is protected and may not be declared: {path}")


def check_scope(
    contract: ScopeContract,
    changed: Iterable[str],
    protected: Sequence[str] = tuple(PROTECTED_GLOBS),
) -> list[str]:
    """Return the paths that were written without authority.

    Declared paths are concrete names, so authority is exact-name equality on
    the normalised form. ``fnmatch.fnmatch`` was used here once; its case
    handling follows the host platform, which made the scope-escape detector
    reach different verdicts on Windows and Linux for the same attempt. The
    result is deliberately a list rather than a boolean so the ledger can
    record exactly what escaped.
    """
    declared = {normalise(path) for path in contract.allowed_paths}
    escaped: list[str] = []
    for path in sorted(set(changed)):
        if is_protected(path, protected):
            escaped.append(path)
            continue
        if normalise(path) not in declared:
            escaped.append(path)
    return escaped
