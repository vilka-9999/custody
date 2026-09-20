"""The loop: propose under contract, act, verify, adjudicate, keep or revert.

This is where the separation of powers is enforced. The remediator proposes
and writes; the harness decides whether anything it wrote survives; the
auditor rules on what happened. No component can perform another's job, and
the remediator never learns whether its own output was accepted until after
the ruling is recorded.

Safety is structural rather than advisory. The harness refuses to run against
a dirty tree or a default branch, refuses a contract that claims protected
territory, and reverts in full on any failed gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from custody import gitio
from custody.auditor.detectors import DiffContext, run_detectors
from custody.auditor.verdict import Judgment, Ruling, adjudicate
from custody.findings import Finding
from custody.ledger import Ledger
from custody.remediator.contract import (
    ScopeContract,
    ScopeViolation,
    is_integrity_critical,
    validate_contract,
)
from custody.surveyor.runner import survey
from custody.testing import run_tests

PROTECTED_BRANCHES = frozenset({"main", "master", "trunk", "develop"})
"""Branches the harness refuses to modify without an explicit override."""


class HarnessRefusal(RuntimeError):
    """Raised when preconditions for a safe run are not met."""


@dataclass(frozen=True)
class Proposal:
    """What a remediator offers for one finding.

    Attributes:
        contract: The authority the attempt claims.
        files: Full replacement contents, keyed by repository-relative path.
        declared_cost_usd: What the remediator says the proposal cost.
        measured_cost_usd: What token accounting actually measured.
        notes: Anything the remediator wants recorded.
    """

    contract: ScopeContract
    files: Dict[str, str]
    declared_cost_usd: float = 0.0
    measured_cost_usd: float = 0.0
    notes: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CaseResult:
    """The outcome of adjudicating one finding."""

    finding: Finding
    judgment: Judgment
    committed: bool
    sha: str = ""


def preflight(repo: Path, allow_default_branch: bool = False) -> str:
    """Verify the repository is safe to modify and return the base SHA.

    Raises:
        HarnessRefusal: If the tree is dirty, untracked by git, or checked out
            on a default branch. Refusing here is cheaper than reverting later,
            and a dirty tree makes the diff meaningless as evidence.
    """
    repo = Path(repo)
    if not gitio.is_repo(repo):
        raise HarnessRefusal("%s is not a git repository" % repo)
    dirty = gitio.dirty_paths(repo)
    if dirty:
        raise HarnessRefusal(
            "working tree has uncommitted changes (%s); commit or stash them first"
            % ", ".join(dirty[:4])
        )
    branch = gitio.current_branch(repo)
    if branch in PROTECTED_BRANCHES and not allow_default_branch:
        raise HarnessRefusal(
            "refusing to modify the %r branch; check out a scratch branch first" % branch
        )
    return gitio.head_sha(repo)


def _capture(repo: Path, paths: Sequence[str]) -> Dict[str, str]:
    """Read the current contents of ``paths``, skipping ones that do not exist."""
    captured: Dict[str, str] = {}
    for rel in paths:
        candidate = repo / rel
        try:
            if candidate.is_file():
                captured[rel] = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return captured


def _apply(repo: Path, files: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """Write proposed file contents, returning what was written and what was refused.

    Two writes never happen. A path resolving outside the repository is
    skipped, so a traversal in a proposal cannot reach the filesystem even if
    contract validation were bypassed. An integrity-critical path - the ledger
    or the auditor's own source - is also refused, because an agent that can
    edit the record of its conduct cannot be meaningfully audited afterwards.

    Everything else is allowed through and adjudicated. That asymmetry is
    deliberate: detection is the point, but it only means anything while the
    evidence is beyond the agent's reach.
    """
    written: List[str] = []
    refused: List[str] = []
    root = repo.resolve()
    for rel, content in sorted(files.items()):
        if is_integrity_critical(rel):
            refused.append(rel)
            continue
        target = (root / rel).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            refused.append(rel)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written.append(rel)
    return written, refused


def run_case(
    repo: Path,
    finding: Finding,
    proposal: Proposal,
    ledger: Ledger,
    base_sha: str,
    findings_before: List[Finding],
    commit: bool = True,
) -> CaseResult:
    """Apply one proposal, verify it, rule on it, and keep or revert it."""
    repo = Path(repo)
    ledger.append(
        "harness", "case.opened", target=finding.id,
        detail={"rule": finding.rule, "location": finding.location(),
                "severity": finding.severity.value},
    )

    try:
        validate_contract(proposal.contract)
    except ScopeViolation as exc:
        judgment = Judgment(
            finding.id, Ruling.REJECTED,
            "Contract claimed territory it may not have: %s" % exc,
        )
        ledger.append(
            "auditor", "case.ruled", target=finding.id, verdict=judgment.ruling.value,
            detail=judgment.to_dict(),
        )
        return CaseResult(finding, judgment, committed=False)

    ledger.append(
        "remediator", "contract.declared", target=finding.id,
        detail=proposal.contract.to_dict(),
        cost_usd=proposal.measured_cost_usd,
    )

    before = _capture(repo, list(proposal.files.keys()))
    written, refused = _apply(repo, proposal.files)
    # The ledger lives inside the repository but is written by the harness, not
    # by the agent, so it is excluded from the diff the auditor examines. The
    # agent cannot write there: _apply refuses integrity-critical paths.
    changed = [
        path for path in gitio.changed_files(repo, base_sha)
        if not is_integrity_critical(path)
    ]
    ledger.append(
        "remediator", "files.written", target=finding.id, files_touched=written,
        detail={"declared": sorted(proposal.contract.allowed_paths), "refused": refused},
    )
    if refused:
        ledger.append(
            "harness", "write.refused", target=finding.id,
            detail={"paths": refused, "reason": "integrity-critical path"},
        )

    outcome = run_tests(repo)
    ledger.append(
        "harness", "tests.run", target=finding.id, detail=outcome.to_dict(),
    )

    after_survey = survey(repo)
    ledger.append(
        "surveyor", "survey.completed", target=finding.id,
        detail={"findings": len(after_survey.findings), "complete": after_survey.complete},
    )

    context = DiffContext(
        contract=proposal.contract,
        changed=changed,
        before=before,
        after=_capture(repo, changed),
        findings_before=findings_before,
        findings_after=after_survey.findings,
        tests_ran=outcome.ran,
        tests_passed=outcome.passed,
        declared_cost_usd=proposal.declared_cost_usd,
        measured_cost_usd=proposal.measured_cost_usd,
    )
    detections = run_detectors(context)
    judgment = adjudicate(context, detections, survey_ran=after_survey.complete)

    keep = judgment.ruling is Ruling.PROVEN and commit
    sha = ""
    if keep:
        try:
            sha = gitio.commit_all(repo, "custody: fix %s (%s)" % (finding.id, finding.rule))
        except gitio.GitError:
            keep = False
    if not keep:
        gitio.restore_to(repo, base_sha)

    ledger.append(
        "auditor", "case.ruled", target=finding.id, verdict=judgment.ruling.value,
        files_touched=written, detail=judgment.to_dict(),
    )
    ledger.append(
        "harness", "case.closed", target=finding.id,
        detail={"kept": keep, "sha": sha, "reverted": not keep},
    )
    return CaseResult(finding, judgment, committed=keep, sha=sha)


def summarise_run(results: List[CaseResult], ledger: Ledger) -> Dict[str, object]:
    """Return counts that distinguish what was checked from what was found."""
    counts: Dict[str, int] = {ruling.value: 0 for ruling in Ruling}
    for result in results:
        counts[result.judgment.ruling.value] += 1
    report = ledger.verify()
    # An empty chain verifies as intact, so entry count is reported beside it.
    # A run that adjudicated cases but recorded nothing is a destroyed audit
    # trail, not a clean result, and must never read as one.
    return {
        "cases": len(results),
        "committed": sum(1 for r in results if r.committed),
        "rulings": counts,
        "spend_usd": ledger.total_cost(),
        "ledger_intact": report.intact,
        "ledger_entries": report.entries,
        "ledger_recorded": report.intact and (report.entries > 0 or not results),
    }
