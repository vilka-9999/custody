"""Walk a repository and collect every deterministic finding.

The walk is ordered and its exclusions are fixed, so two runs over the same
tree visit the same files in the same sequence and produce byte-identical
results. Reproducibility is what lets the auditor re-survey after a change and
compare the two runs honestly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from custody.findings import Finding, Pillar, sort_findings
from custody.surveyor.ast_rules import survey_source
from custody.surveyor.secrets import survey_secrets

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

MAX_FILES = 5000
"""Upper bound on files visited, so a pathological tree cannot hang a run."""


@dataclass(frozen=True)
class SurveyResult:
    """What one survey examined and what it found.

    Counting what was checked is as important as reporting what was found: a
    survey that visited nothing must never be mistaken for a clean repository.
    """

    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    python_files: int = 0
    skipped: List[str] = field(default_factory=list)
    complete: bool = True

    def by_pillar(self) -> Dict[str, int]:
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
        return "%d files scanned (%d Python); %d findings (%s)" % (
            self.files_scanned, self.python_files, len(self.findings), detail,
        )


def iter_files(root: Path, excluded: Sequence[str] = ()) -> List[Path]:
    """Return every scannable file under ``root`` in a stable order."""
    skip = EXCLUDED_DIRS | set(excluded)
    collected: List[Path] = []
    for path in sorted(root.rglob("*")):
        if len(collected) >= MAX_FILES:
            break
        if not path.is_file():
            continue
        if any(part in skip for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            collected.append(path)
    return collected


def survey(root: Path, excluded: Optional[Sequence[str]] = None) -> SurveyResult:
    """Run every deterministic rule over the repository at ``root``."""
    root = Path(root).resolve()
    if not root.is_dir():
        return SurveyResult(complete=False, skipped=["%s is not a directory" % root])

    findings: List[Finding] = []
    skipped: List[str] = []
    python_files = 0
    files = iter_files(root, excluded or ())

    for path in files:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            skipped.append(str(path))
            continue
        try:
            findings.extend(survey_secrets(path, rel))
            if path.suffix == ".py":
                python_files += 1
                findings.extend(survey_source(path, rel))
        except OSError as exc:
            skipped.append("%s (%s)" % (rel, exc))

    return SurveyResult(
        findings=sort_findings(findings),
        files_scanned=len(files),
        python_files=python_files,
        skipped=skipped,
        complete=len(files) < MAX_FILES,
    )
