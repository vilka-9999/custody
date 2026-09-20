"""Command-line entry point for Custody."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional, Sequence

from custody import __version__
from custody.findings import Finding
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

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments and dispatch to the chosen command."""
    args = build_parser().parse_args(argv)
    return int(args.func(args))
