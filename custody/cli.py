"""Command-line entry point for Custody."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from custody import __version__, gitio
from custody.findings import Finding, sort_findings
from custody.ledger import Ledger
from custody.surveyor.runner import survey

if TYPE_CHECKING:
    from custody.harness import CaseResult, Proposal

ProposalFn = Callable[[Path, Finding], "Proposal | None"]
"""The remediator interface: one finding in, a proposal or a decline out."""

DEFAULT_LEDGER = Path(".custody") / "ledger.jsonl"


def _print_findings(findings: list[Finding], limit: int) -> None:
    """Print findings in severity order, truncated to ``limit``."""
    for finding in findings[:limit]:
        print(
            "  %-8s %-34s %-42s %s"
            % (finding.severity.value, finding.rule, finding.location(), finding.message)
        )
    if len(findings) > limit:
        print("  ... %d more (raise --limit to see them)" % (len(findings) - limit))


def cmd_survey(args: argparse.Namespace) -> int:
    """Run the deterministic survey and report what was examined."""
    result = survey(Path(args.repo))
    ledger = Ledger(Path(args.repo) / DEFAULT_LEDGER)
    ledger.append(
        "surveyor", "survey.completed", target=str(args.repo),
        detail={
            "files_scanned": result.files_scanned,
            "python_files": result.python_files,
            "findings": len(result.findings),
            "complete": result.complete,
            "by_pillar": result.by_pillar(),
        },
    )

    if args.json:
        print(json.dumps(
            {"summary": result.summary(),
             "findings": [f.to_dict() for f in result.findings]},
            indent=2, sort_keys=True,
        ))
        return 0

    print(f"Custody survey: {Path(args.repo).resolve()}")
    print(result.summary())
    if result.skipped:
        print("skipped %d path(s); this is not a clean result for them" % len(result.skipped))
    print("")
    _print_findings(result.findings, args.limit)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Recompute the ledger hash chain and report whether it reconciles."""
    from custody.ledger import LedgerError

    path = Path(args.repo) / DEFAULT_LEDGER
    if not path.exists():
        print(f"no ledger at {path} - nothing has been recorded")
        return 1
    print(f"Custody ledger: {path}")
    try:
        ledger = Ledger(path)
        report = ledger.verify()
        spend = ledger.total_cost()
    except LedgerError as exc:
        # A file that cannot even be read as a ledger is a broken chain, not
        # a crash: the verdict must be printed, not raised.
        print(f"chain BROKEN: {exc}")
        return 2
    print(report.summary())
    print(f"recorded spend: ${spend:.4f}")
    return 0 if report.intact else 2


def cmd_eval(_args: argparse.Namespace) -> int:
    """Run the auditor against the ground-truth fixtures."""
    from custody.evaluation import main as run_eval

    return run_eval()


def cmd_trial(_args: argparse.Namespace) -> int:
    """Run the adversarial trial: seven attempts, one honest."""
    from custody.trial import main as run_trial_main

    return run_trial_main()


def cmd_console(args: argparse.Namespace) -> int:
    """Serve the read-only ledger dashboard."""
    from custody.console import serve

    serve(Path(args.repo) / DEFAULT_LEDGER, port=args.port)
    return 0


def _key(finding: Finding) -> tuple[str, str, object]:
    """Return an identity for a finding that survives edits near it.

    Ids are content-anchored, so they already survive line drift; this key
    additionally survives the flagged line itself being rewritten by a failed
    attempt, by preferring the symbol name when one is known. That keeps
    "already attempted" meaningful across a re-survey.
    """
    symbol = finding.detail.get("symbol") or finding.detail.get("function")
    return (finding.rule, finding.path, symbol or finding.line)


def _select_remediator(args: argparse.Namespace) -> tuple[str, ProposalFn]:
    """Choose a remediator and return its name alongside a proposal function.

    Falling back to the deterministic remediator when no key is present is a
    reduction in capability, not a failure, so it is announced rather than
    silently substituted.
    """
    from custody.remediator import deterministic
    from custody.remediator.agent import available
    from custody.remediator.agent import propose as llm_propose

    if args.offline or not available():
        if not args.offline:
            print("ANTHROPIC_API_KEY is not set; using the deterministic remediator.")
            print("It fixes a subset of rules and declines the rest.")
        return "deterministic", lambda repo, finding: deterministic.propose(repo, finding)

    return f"model:{args.model}", lambda repo, finding: llm_propose(
        repo, finding, model=args.model, effort=args.effort
    )


def _obtain_proposal(
    repo: Path, finding: Finding, make_proposal: ProposalFn, ledger: Ledger
) -> Proposal | None:
    """Ask the chosen remediator for a proposal, recording why it declined.

    A decline and a failure are recorded as different events. The first means
    the remediator judged itself unable to repair this correctly, which is a
    result; the second means the request itself broke, which is not.
    """
    from custody.llm import LLMError
    from custody.remediator.agent import ProposalError

    try:
        proposal = make_proposal(repo, finding)
    except (ProposalError, LLMError) as exc:
        ledger.append(
            "remediator", "proposal.failed", target=finding.id,
            detail={"error": str(exc), "rule": finding.rule},
        )
        print(f"    proposal failed: {exc}")
        return None

    if proposal is None:
        ledger.append(
            "remediator", "proposal.declined", target=finding.id,
            detail={"reason": "no fixer available for this rule", "rule": finding.rule},
        )
        print("    declined (no fixer for this rule)")
    return proposal


def _run_attempts(
    repo: Path,
    limit: int,
    make_proposal: ProposalFn,
    ledger: Ledger,
    commit: bool,
) -> tuple[list[CaseResult], int, int]:
    """Attempt findings one at a time, re-deriving the queue before each.

    A committed fix shifts the line numbers of everything below it in the same
    file, so a list surveyed once goes stale after the first commit and later
    findings silently point at the wrong lines. Re-surveying costs a few
    milliseconds and keeps every location true at the moment it is acted on.

    Returns:
        The adjudicated cases, how many findings were declined, and how many
        attempts were made. All three are reported, because "3 fixed" means
        something different after 3 attempts than after 30.
    """
    from custody.harness import run_case

    results: list[CaseResult] = []
    attempted: set[tuple[str, str, object]] = set()
    declined = 0
    attempts = 0

    while attempts < limit:
        current = survey(repo)
        if not current.complete:
            print("survey did not complete mid-run; stopping rather than guessing")
            break
        pending = [f for f in sort_findings(current.findings) if _key(f) not in attempted]
        if not pending:
            break

        finding = pending[0]
        attempted.add(_key(finding))
        attempts += 1
        base_for_case = gitio.head_sha(repo)
        print("  %s  %-34s %s" % (finding.id, finding.rule, finding.location()))

        proposal = _obtain_proposal(repo, finding, make_proposal, ledger)
        if proposal is None:
            declined += 1
            continue

        case = run_case(
            repo, finding, proposal, ledger, base_for_case, current.findings, commit=commit
        )
        results.append(case)
        detectors = sorted({d.detector for d in case.judgment.detections})
        print("    %-22s %s" % (
            case.judgment.ruling.value, ", ".join(detectors) or case.judgment.reason
        ))

    return results, declined, attempts


def cmd_harden(args: argparse.Namespace) -> int:
    """Run the full loop: propose under contract, verify, adjudicate, keep or revert."""
    from custody.harness import HarnessRefusalError, preflight, summarise_run

    repo = Path(args.repo)
    remediator_name, make_proposal = _select_remediator(args)

    try:
        base_sha = preflight(repo, allow_default_branch=args.allow_default_branch)
    except HarnessRefusalError as exc:
        print(f"refusing to run: {exc}")
        return 1

    result = survey(repo)
    if not result.complete:
        print("survey did not complete; refusing to act on partial evidence")
        return 1

    if not result.findings:
        print(result.summary())
        print("nothing to remediate")
        return 0

    ledger = Ledger(repo / DEFAULT_LEDGER)
    ledger.append(
        "harness", "run.started", target=str(repo),
        detail={"base_sha": base_sha, "branch": gitio.current_branch(repo),
                "findings_at_start": len(result.findings), "limit": args.limit,
                "remediator": remediator_name, "dry_run": bool(args.dry_run)},
    )
    print("Custody harden: up to %d attempt(s) on branch %s via %s"
          % (args.limit, gitio.current_branch(repo), remediator_name))
    if args.dry_run:
        print("dry run: nothing will be committed")
    print("")

    results, declined, attempts = _run_attempts(
        repo, args.limit, make_proposal, ledger, commit=not args.dry_run
    )

    summary = summarise_run(results, ledger)
    findings_now = len(survey(repo).findings)
    detail = summary.to_dict()
    detail.update({
        "declined": declined,
        "attempts": attempts,
        "findings_at_start": len(result.findings),
        "findings_now": findings_now,
    })
    ledger.append("harness", "run.finished", target=str(repo), detail=detail)
    print("")
    print("  %d adjudicated, %d declined, over %d attempt(s)"
          % (len(results), declined, attempts))
    print("  findings %d -> %d" % (len(result.findings), findings_now))
    for ruling, count in sorted(summary.rulings.items()):
        print("  %-22s %d" % (ruling, count))
    print("  committed              %d" % summary.committed)
    print(f"  spend                  ${summary.spend_usd:.4f}")
    print("  ledger entries         %d" % summary.ledger_entries)
    print(f"  ledger recorded        {summary.ledger_recorded}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="custody", description="Chain of custody for machine-written code."
    )
    parser.add_argument("--version", action="version", version=f"custody {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    survey_parser = subparsers.add_parser("survey", help="run the deterministic survey")
    survey_parser.add_argument("repo", nargs="?", default=".", help="repository to examine")
    survey_parser.add_argument("--limit", type=int, default=25, help="findings to print")
    survey_parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    survey_parser.set_defaults(func=cmd_survey)

    verify_parser = subparsers.add_parser("verify", help="verify the ledger hash chain")
    verify_parser.add_argument("repo", nargs="?", default=".", help="repository to check")
    verify_parser.set_defaults(func=cmd_verify)

    eval_parser = subparsers.add_parser("eval", help="score the auditor on known fixtures")
    eval_parser.set_defaults(func=cmd_eval)

    trial_parser = subparsers.add_parser(
        "trial", help="run the adversarial trial (offline, no API key)"
    )
    trial_parser.set_defaults(func=cmd_trial)

    console_parser = subparsers.add_parser("console", help="serve the ledger dashboard")
    console_parser.add_argument("repo", nargs="?", default=".", help="repository to read")
    console_parser.add_argument("--port", type=int, default=8765, help="port to listen on")
    console_parser.set_defaults(func=cmd_console)

    harden_parser = subparsers.add_parser(
        "harden", help="remediate findings under contract and adjudication"
    )
    harden_parser.add_argument("repo", nargs="?", default=".", help="repository to harden")
    harden_parser.add_argument("--limit", type=int, default=3, help="findings to attempt")
    harden_parser.add_argument("--model", default="claude-opus-5", help="model for the agent")
    harden_parser.add_argument(
        "--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"],
        help="reasoning effort",
    )
    harden_parser.add_argument(
        "--dry-run", action="store_true", help="adjudicate but never commit"
    )
    harden_parser.add_argument(
        "--offline", action="store_true",
        help="use the deterministic remediator; no API key, no network",
    )
    harden_parser.add_argument(
        "--allow-default-branch", action="store_true",
        help="permit running on main/master (refused by default)",
    )
    harden_parser.set_defaults(func=cmd_harden)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and dispatch to the chosen command."""
    args = build_parser().parse_args(argv)
    return int(args.func(args))
