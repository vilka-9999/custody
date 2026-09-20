"""Walk a repository and collect every deterministic finding.

The walk is ordered and its exclusions are fixed, so two runs over the same
tree visit the same files in the same sequence and produce byte-identical
results. Reproducibility is what lets the auditor re-survey after a change and
compare the two runs honestly.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from custody.findings import Finding, Pillar, sort_findings
from custody.surveyor.ast_rules import survey_source
from custody.surveyor.secrets import MAX_SCAN_BYTES, survey_secrets

EXCLUDED_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", ".tox", ".venv", "venv", "env", "node_modules",
        "dist", "build", ".eggs", ".custody", "site-packages",
    }
)
"""Directory names never descended into."""

TEXT_SUFFIXES = frozenset(
    {".py", ".toml", ".cfg", ".ini", ".yml", ".yaml", ".json", ".env", ".sh", ".txt", ".md"}
)
"""Suffixes scanned for committed credentials."""

DOTFILE_PREFIXES = (".env",)
"""File names collected by name rather than suffix.

``Path(".env").suffix`` is empty, so a suffix rule alone never scans the
single most common place a credential is committed. ``.env`` and variants
like ``.env.local`` are matched on the name instead.
"""


def _is_scannable(path: Path) -> bool:
    """Return whether ``path`` is a text file the survey examines."""
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    name = path.name.lower()
    return any(name == prefix or name.startswith(prefix + ".") for prefix in DOTFILE_PREFIXES)

MAX_FILES = 5000
"""Upper bound on files visited, so a pathological tree cannot hang a run."""


@dataclass(frozen=True)
class SurveyResult:
    """What one survey examined and what it found.

    Counting what was checked is as important as reporting what was found: a
    survey that visited nothing must never be mistaken for a clean repository.
    """

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    python_files: int = 0
    skipped: list[str] = field(default_factory=list)
    complete: bool = True

    def by_pillar(self) -> dict[str, int]:
        """Return a count of findings per pillar, including empty pillars."""
        counts = {pillar.value: 0 for pillar in Pillar}
        for finding in self.findings:
            counts[finding.pillar.value] += 1
        return counts

    def summary(self) -> str:
        """Return a summary that distinguishes clean from unchecked."""
        if not self.complete:
            return (
                "survey incomplete: %d files scanned before stopping - "
                "this is not a clean result" % self.files_scanned
            )
        counts = self.by_pillar()
        detail = ", ".join("%s %d" % (name.lower(), n) for name, n in sorted(counts.items()))
        line = "%d files scanned (%d Python); %d findings (%s)" % (
            self.files_scanned, self.python_files, len(self.findings), detail,
        )
        if self.skipped:
            line += "; %d path(s) skipped - not examined, not clean" % len(self.skipped)
        return line


def iter_files(root: Path, excluded: Sequence[str] = ()) -> tuple[list[Path], bool]:
    """Return every scannable file under ``root`` in a stable order.

    The second element reports whether the walk was truncated at
    :data:`MAX_FILES` with scannable files still remaining. A tree that holds
    exactly the limit is complete, not truncated; an earlier version inferred
    truncation from the count alone and misreported that case.
    """
    skip = EXCLUDED_DIRS | set(excluded)
    collected: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in skip for part in path.parts):
            continue
        if not _is_scannable(path):
            continue
        if len(collected) >= MAX_FILES:
            return collected, True
        collected.append(path)
    return collected, False


def survey(root: Path, excluded: Sequence[str] | None = None) -> SurveyResult:
    """Run every deterministic rule over the repository at ``root``."""
    root = Path(root).resolve()
    if not root.is_dir():
        return SurveyResult(complete=False, skipped=[f"{root} is not a directory"])

    findings: list[Finding] = []
    skipped: list[str] = []
    python_files = 0
    files, truncated = iter_files(root, excluded or ())

    for path in files:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            skipped.append(str(path))
            continue
        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                skipped.append(f"{rel} (exceeds {MAX_SCAN_BYTES} bytes; not scanned)")
                continue
            findings.extend(survey_secrets(path, rel))
            if path.suffix.lower() == ".py":
                python_files += 1
                source_findings = survey_source(path, rel)
                if source_findings is None:
                    skipped.append(f"{rel} (does not parse as Python; AST rules did not run)")
                else:
                    findings.extend(source_findings)
        except OSError as exc:
            skipped.append(f"{rel} ({exc})")

    return SurveyResult(
        findings=sort_findings(findings),
        files_scanned=len(files),
        python_files=python_files,
        skipped=skipped,
        complete=not truncated,
    )
