"""Command-line entry point for Custody."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from custody import __version__, gitio
from custody.findings import Finding, sort_findings
from custody.ledger import Ledger
from custody.surveyor.runner import survey

DEFAULT_LEDGER = Path(".custody") / "ledger.jsonl"


def _print_findings(findings: List[Finding], limit: int) -> None:
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

    print("Custody survey: %s" % Path(args.repo).resolve())
    print(result.summary())
    if result.skipped:
        print("skipped %d path(s); this is not a clean result for them" % len(result.skipped))
    print("")
    _print_findings(result.findings, args.limit)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Recompute the ledger hash chain and report whether it reconciles."""
    path = Path(args.repo) / DEFAULT_LEDGER
    if not path.exists():
        print("no ledger at %s - nothing has been recorded" % path)
        return 1
    ledger = Ledger(path)
    report = ledger.verify()
    print("Custody ledger: %s" % path)
    print(report.summary())
    print("recorded spend: $%.4f" % ledger.total_cost())
    return 0 if report.intact else 2


def cmd_eval(args: argparse.Namespace) -> int:
    """Run the auditor against the ground-truth fixtures."""
    from custody.evaluation import main as run_eval

    return run_eval()


def cmd_trial(args: argparse.Namespace) -> int:
    """Run the adversarial trial: seven attempts, one honest."""
    from custody.trial import main as run_trial_main

    return run_trial_main()


def cmd_console(args: argparse.Namespace) -> int:
    """Serve the read-only ledger dashboard."""
    from custody.console import serve

    serve(Path(args.repo) / DEFAULT_LEDGER, port=args.port)
    return 0


def _key(finding: Finding) -> tuple:
    """Return an identity for a finding that survives line-number drift.

    A finding's id is derived from its location, so committing a fix above it
    changes the id of everything below. Keying on the symbol when one is known
    keeps "already attempted" meaningful across a re-survey.
    """
    symbol = finding.detail.get("symbol") or finding.detail.get("function")
    return (finding.rule, finding.path, symbol or finding.line)


def _select_remediator(args: argparse.Namespace) -> Tuple[str, Callable]:
    """Choose a remediator and return its name alongside a proposal function.

    Falling back to the deterministic remediator when no key is present is a
    reduction in capability, not a failure, so it is announced rather than
    silently substituted.
    """
    from custody.remediator import deterministic
    from custody.remediator.agent import available, propose as llm_propose

    if args.offline or not available():
        if not args.offline:
            print("ANTHROPIC_API_KEY is not set; using the deterministic remediator.")
            print("It fixes a subset of rules and declines the rest.")
        return "deterministic", lambda repo, finding: deterministic.propose(repo, finding)

    return "model:%s" % args.model, lambda repo, finding: llm_propose(
        repo, finding, model=args.model, effort=args.effort
    )


def cmd_harden(args: argparse.Namespace) -> int:
    """Run the full loop: propose under contract, verify, adjudicate, keep or revert."""
    from custody.harness import HarnessRefusal, preflight, run_case, summarise_run
    from custody.llm import LLMError
    from custody.remediator.agent import ProposalError

    repo = Path(args.repo)
    remediator_name, make_proposal = _select_remediator(args)

    try:
        base_sha = preflight(repo, allow_default_branch=args.allow_default_branch)
    except HarnessRefusal as exc:
        print("refusing to run: %s" % exc)
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

    results = []
    declined = 0
    attempted: set = set()
    attempts = 0

    # The queue is re-derived before every attempt. A committed fix shifts the
    # line numbers of everything below it in the same file, so a list surveyed
    # once goes stale after the first commit and later findings silently point
    # at the wrong lines. Re-surveying costs a few milliseconds and keeps every
    # location true at the moment it is acted on.
    while attempts < args.limit:
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

        try:
            proposal = make_proposal(repo, finding)
        except (ProposalError, LLMError) as exc:
            ledger.append(
                "remediator", "proposal.failed", target=finding.id,
                detail={"error": str(exc), "rule": finding.rule},
            )
            print("    proposal failed: %s" % exc)
            continue
        if proposal is None:
            declined += 1
            ledger.append(
                "remediator", "proposal.declined", target=finding.id,
                detail={"reason": "no fixer available for this rule", "rule": finding.rule},
            )
            print("    declined (no fixer for this rule)")
            continue

        case = run_case(
            repo, finding, proposal, ledger, base_for_case, current.findings,
            commit=not args.dry_run,
        )
        results.append(case)
        detectors = sorted({d.detector for d in case.judgment.detections})
        print("    %-22s %s" % (
            case.judgment.ruling.value, ", ".join(detectors) or case.judgment.reason
        ))

    summary = summarise_run(results, ledger)
    summary["declined"] = declined
    summary["attempts"] = attempts
    summary["findings_at_start"] = len(result.findings)
    summary["findings_now"] = len(survey(repo).findings)
    ledger.append("harness", "run.finished", target=str(repo), detail=summary)
    print("")
    print("  %d adjudicated, %d declined, over %d attempt(s)"
          % (len(results), declined, attempts))
    print("  findings %d -> %d" % (summary["findings_at_start"], summary["findings_now"]))
    for ruling, count in sorted(summary["rulings"].items()):
        print("  %-22s %d" % (ruling, count))
    print("  committed              %d" % summary["committed"])
    print("  spend                  $%.4f" % summary["spend_usd"])
    print("  ledger entries         %d" % summary["ledger_entries"])
    print("  ledger recorded        %s" % summary["ledger_recorded"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="custody", description="Chain of custody for machine-written code."
    )
    parser.add_argument("--version", action="version", version="custody %s" % __version__)
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments and dispatch to the chosen command."""
    args = build_parser().parse_args(argv)
    return int(args.func(args))
