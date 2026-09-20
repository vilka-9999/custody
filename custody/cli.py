"""Command-line entry point for Custody."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional, Sequence

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


def cmd_harden(args: argparse.Namespace) -> int:
    """Run the full loop: propose under contract, verify, adjudicate, keep or revert."""
    from custody.harness import HarnessRefusal, preflight, run_case, summarise_run
    from custody.llm import LLMError
    from custody.remediator.agent import ProposalError, available, propose

    repo = Path(args.repo)
    if not available():
        print("ANTHROPIC_API_KEY is not set.")
        print("Run 'custody trial' for the offline adversarial demonstration instead.")
        return 1

    try:
        base_sha = preflight(repo, allow_default_branch=args.allow_default_branch)
    except HarnessRefusal as exc:
        print("refusing to run: %s" % exc)
        return 1

    result = survey(repo)
    if not result.complete:
        print("survey did not complete; refusing to act on partial evidence")
        return 1

    findings = sort_findings(result.findings)[: args.limit]
    if not findings:
        print(result.summary())
        print("nothing to remediate")
        return 0

    ledger = Ledger(repo / DEFAULT_LEDGER)
    ledger.append(
        "harness", "run.started", target=str(repo),
        detail={"base_sha": base_sha, "branch": gitio.current_branch(repo),
                "queued": len(findings), "model": args.model},
    )
    print("Custody harden: %d finding(s) queued on branch %s"
          % (len(findings), gitio.current_branch(repo)))
    print("")

    results = []
    for finding in findings:
        print("  %s  %s" % (finding.id, finding.location()))
        try:
            proposal = propose(repo, finding, model=args.model, effort=args.effort)
        except (ProposalError, LLMError) as exc:
            ledger.append(
                "remediator", "proposal.failed", target=finding.id,
                detail={"error": str(exc)},
            )
            print("    proposal failed: %s" % exc)
            continue
        case = run_case(
            repo, finding, proposal, ledger, base_sha, result.findings,
            commit=not args.dry_run,
        )
        results.append(case)
        detectors = sorted({d.detector for d in case.judgment.detections})
        print("    %-22s %s" % (
            case.judgment.ruling.value, ", ".join(detectors) or "no detections"
        ))

    summary = summarise_run(results, ledger)
    ledger.append("harness", "run.finished", target=str(repo), detail=summary)
    print("")
    for ruling, count in sorted(summary["rulings"].items()):
        print("  %-22s %d" % (ruling, count))
    print("  committed              %d" % summary["committed"])
    print("  spend                  $%.4f" % summary["spend_usd"])
    print("  ledger intact          %s" % summary["ledger_intact"])
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
        "--allow-default-branch", action="store_true",
        help="permit running on main/master (refused by default)",
    )
    harden_parser.set_defaults(func=cmd_harden)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments and dispatch to the chosen command."""
    args = build_parser().parse_args(argv)
    return int(args.func(args))
