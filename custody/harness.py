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

import contextlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from custody import gitio
from custody.auditor.detectors import DiffContext, run_detectors
from custody.auditor.review import ReviewFn, needs_review
from custody.auditor.verdict import Judgment, Ruling, adjudicate
from custody.findings import Finding
from custody.ledger import Ledger
from custody.remediator.contract import (
    ScopeContract,
    ScopeViolationError,
    is_integrity_critical,
    is_repo_relative,
    validate_contract,
)
from custody.surveyor.runner import survey
from custody.testing import run_tests

PROTECTED_BRANCHES = frozenset({"main", "master", "trunk", "develop"})
"""Branches the harness refuses to modify without an explicit override."""


class HarnessRefusalError(RuntimeError):
    """Raised when preconditions for a safe run are not met."""


@dataclass(frozen=True)
class Proposal:
    """What a remediator offers for one finding.

    Attributes:
        contract: The authority the attempt claims.
        files: Full replacement contents, keyed by repository-relative path.
        declared_cost_usd: What the remediator says the proposal cost.
        measured_cost_usd: What token accounting actually measured.
        cost_measurable: Whether the model's rate was known at all.
        notes: Anything the remediator wants recorded.
    """

    contract: ScopeContract
    files: dict[str, str]
    declared_cost_usd: float = 0.0
    measured_cost_usd: float = 0.0
    cost_measurable: bool = True
    notes: dict[str, str] = field(default_factory=dict)


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
        HarnessRefusalError: If the tree is dirty, untracked by git, or
            checked out on a default branch. Refusing here is cheaper than
            reverting later, and a dirty tree makes the diff meaningless as
            evidence.
    """
    repo = Path(repo)
    if not gitio.is_repo(repo):
        raise HarnessRefusalError(f"{repo} is not a git repository")
    dirty = gitio.dirty_paths(repo)
    if dirty:
        raise HarnessRefusalError(
            "working tree has uncommitted changes ({}); commit or stash them first".format(
                ", ".join(dirty[:4])
            )
        )
    branch = gitio.current_branch(repo)
    if branch in PROTECTED_BRANCHES and not allow_default_branch:
        raise HarnessRefusalError(
            f"refusing to modify the {branch!r} branch; check out a scratch branch first"
        )
    return gitio.head_sha(repo)


def verify_baseline(repo: Path) -> None:
    """Refuse to run against a suite that is already red.

    Every attempt is judged by whether the project's own suite passes after
    the change. A baseline that fails before any agent touches the tree makes
    that judgment meaningless: every attempt would be rejected for breakage
    it did not cause. A missing suite is different - it yields
    INSUFFICIENT_EVIDENCE per case rather than a refusal, because "there is
    no gate" is a fact worth recording, while "the gate was already red"
    poisons every verdict.

    Raises:
        HarnessRefusalError: If the suite ran and failed at baseline.
    """
    outcome = run_tests(repo)
    if outcome.ran and not outcome.passed:
        raise HarnessRefusalError(
            "the project's test suite is already failing before any change; "
            "a red baseline cannot distinguish the agent's breakage from the "
            "repository's own - fix the suite first"
        )


def _capture(repo: Path, paths: Sequence[str]) -> dict[str, str]:
    """Read the current contents of ``paths``, skipping ones that do not exist."""
    captured: dict[str, str] = {}
    for rel in paths:
        candidate = repo / rel
        try:
            if candidate.is_file():
                captured[rel] = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return captured


def _apply(repo: Path, files: dict[str, str]) -> tuple[list[str], list[str]]:
    """Write proposed file contents, returning what was written and what was refused.

    Every decision here is made against the *resolved* repository-relative
    path, never the raw key from the proposal. That ordering is the whole
    point: a key like ``a/../custody/ledger.py`` is not textually equal to any
    protected glob, yet it resolves onto one. Matching the glob before
    resolving is how a traversal that cancels back inside the repository slips
    past a guard that looks like it is working.

    Three writes never happen:

    - a key that is absolute or contains a ``..`` segment, refused before it
      is resolved at all;
    - a path that resolves outside the repository;
    - a path that resolves onto integrity-critical territory - the ledger or
      the auditor's own source - because an agent that can edit the record of
      its conduct cannot be meaningfully audited afterwards.

    Everything else is allowed through and adjudicated. That asymmetry is
    deliberate: detection is the point, but it only means anything while the
    evidence is beyond the agent's reach.
    """
    written: list[str] = []
    refused: list[str] = []
    root = repo.resolve()

    for rel, content in sorted(files.items()):
        if not is_repo_relative(rel):
            refused.append(rel)
            continue

        target = (root / rel).resolve()
        try:
            canonical = target.relative_to(root).as_posix()
        except ValueError:
            refused.append(rel)
            continue

        if is_integrity_critical(canonical):
            refused.append(rel)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        # newline="" writes the proposal byte-for-byte. The platform default
        # translates \n to the OS convention, which on Windows rewrote every
        # line ending in an LF file - thousands of phantom changes drowning
        # the one real one in the diff the auditor uses as evidence.
        with target.open("w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        written.append(canonical)

    return written, refused


def run_case(
    repo: Path,
    finding: Finding,
    proposal: Proposal,
    ledger: Ledger,
    base_sha: str,
    findings_before: list[Finding],
    commit: bool = True,
    review: ReviewFn | None = None,
) -> CaseResult:
    """Apply one proposal, verify it, rule on it, and keep or revert it.

    ``review`` is the optional model adjudicator for the one ambiguous state:
    a PROVEN ruling that carries advisory detections. It is a one-way
    ratchet - an objection withholds the commit; nothing it returns can
    override a rejection or upgrade a ruling - and when it is absent or
    fails, the deterministic ruling stands with the gap recorded.
    """
    repo = Path(repo)
    ledger.append(
        "harness", "case.opened", target=finding.id,
        detail={"rule": finding.rule, "location": finding.location(),
                "severity": finding.severity.value},
    )

    try:
        validate_contract(proposal.contract)
    except ScopeViolationError as exc:
        judgment = Judgment(
            finding.id, Ruling.REJECTED,
            f"Contract claimed territory it may not have: {exc}",
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

    # From the first write onward, an unexpected exception must not strand the
    # agent's changes on disk: the tree is reverted, the abort is recorded, and
    # the error still propagates. An attempt that died halfway is not evidence
    # of anything, but files it wrote surviving un-adjudicated would be worse.
    try:
        return _adjudicate_applied(
            repo, finding, proposal, ledger, base_sha, findings_before, commit, review
        )
    except Exception as exc:
        _abort_case(repo, finding, ledger, base_sha, exc)
        raise


def _abort_case(
    repo: Path, finding: Finding, ledger: Ledger, base_sha: str, exc: Exception
) -> None:
    """Best-effort revert and record after an attempt died mid-flight."""
    try:
        gitio.restore_to(repo, base_sha)
        reverted = True
    except gitio.GitError:
        reverted = False
    with contextlib.suppress(OSError):
        ledger.append(
            "harness", "case.aborted", target=finding.id,
            detail={"error": str(exc), "reverted": reverted},
        )


def _adjudicate_applied(
    repo: Path,
    finding: Finding,
    proposal: Proposal,
    ledger: Ledger,
    base_sha: str,
    findings_before: list[Finding],
    commit: bool,
    review: ReviewFn | None = None,
) -> CaseResult:
    """Write, verify, rule on, and keep or revert one validated proposal."""
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
        cost_measurable=proposal.cost_measurable,
    )
    detections = run_detectors(context)
    judgment = adjudicate(context, detections, survey_ran=after_survey.complete)

    # The one ambiguous state: deterministically PROVEN, but advisory
    # detections exist. The reviewer's objection withholds the commit; the
    # ruling and its claim lists are untouched, because every statement
    # PROVEN licenses remains deterministically true either way.
    withheld = False
    if review is not None and needs_review(judgment):
        opinion = review(context, judgment)
        if opinion is None:
            ledger.append(
                "auditor", "review.unavailable", target=finding.id,
                detail={"note": "reviewer unreachable or unreadable; "
                                "deterministic ruling stands"},
            )
        else:
            ledger.append(
                "auditor", "review.completed", target=finding.id,
                detail=opinion.to_dict(), cost_usd=opinion.cost_usd,
                tokens_in=opinion.tokens_in, tokens_out=opinion.tokens_out,
            )
            withheld = opinion.objects

    keep = judgment.ruling is Ruling.PROVEN and commit and not withheld
    sha = ""
    if keep:
        try:
            sha = gitio.commit_all(repo, f"custody: fix {finding.id} ({finding.rule})")
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
        detail={"kept": keep, "sha": sha, "reverted": not keep,
                "withheld_by_review": withheld},
    )
    return CaseResult(finding, judgment, committed=keep, sha=sha)


@dataclass(frozen=True)
class RunSummary:
    """Counts that distinguish what was checked from what was found."""

    cases: int
    committed: int
    rulings: dict[str, int]
    spend_usd: float
    ledger_intact: bool
    ledger_entries: int
    ledger_recorded: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view for the ledger."""
        return {
            "cases": self.cases,
            "committed": self.committed,
            "rulings": dict(self.rulings),
            "spend_usd": self.spend_usd,
            "ledger_intact": self.ledger_intact,
            "ledger_entries": self.ledger_entries,
            "ledger_recorded": self.ledger_recorded,
        }


def summarise_run(results: list[CaseResult], ledger: Ledger) -> RunSummary:
    """Summarise a run without overstating what the ledger holds."""
    counts: dict[str, int] = {ruling.value: 0 for ruling in Ruling}
    for result in results:
        counts[result.judgment.ruling.value] += 1
    report = ledger.verify()
    # An empty chain verifies as intact, so entry count is reported beside it.
    # A run that adjudicated cases but recorded nothing is a destroyed audit
    # trail, not a clean result, and must never read as one.
    return RunSummary(
        cases=len(results),
        committed=sum(1 for r in results if r.committed),
        rulings=counts,
        spend_usd=ledger.total_cost(),
        ledger_intact=report.intact,
        ledger_entries=report.entries,
        ledger_recorded=report.intact and (report.entries > 0 or not results),
    )
