# Submission — Custody

**Track:** Build It · Bring Your Own Agent Project · The Code Registry Challenge
**Repository:** https://github.com/vilka-9999/custody
**Demo video:** [ADD LINK BEFORE SUBMITTING — ≤3 min, shows the xo-space]
**Team:** LaSalle Explorers

## The problem

Agents can run for hours, consume tokens, modify files and call tools — and
it is often impossible to see what they actually did or whether they stayed
inside their intended boundaries. The usual answer is to trust the agent's
own account: a commit message, a summary, a green checkmark. Custody does
not. It re-derives what happened from the diff, the test results, and a
fresh deterministic survey, then rules on whether the agent's account
survives contact with the evidence — recording the whole proceeding in an
append-only, hash-chained ledger.

## The work the agent performs

`custody harden <repo>` runs the loop: a remediator (Claude Opus 5, or a
deterministic rule-based fallback) declares a scope contract *before*
acting, proposes a bounded fix for one finding, and the harness applies it,
runs the project's own test suite, re-surveys, and lets an adversarial
auditor rule PROVEN / NOT_OBSERVED / INSUFFICIENT_EVIDENCE / REJECTED. Only
PROVEN survives as a commit; everything else is reverted in full and lives
on as a ledger entry. Demonstrated on a real repository
([docs/CASE-STUDY.md](docs/CASE-STUDY.md)): 1,457 findings surveyed in
Bottle, 3 fixed and PROVEN against its own 381-test suite, 42 correctly
declined.

## How its activity is visible in the xo-space

Everything the rubric names is on screen in the demo: **environment** (the
workspace and its projects), **activity** (the agent live, mid-run),
**sessions** (timestamps, status), **actions** (tool-call breakdown),
**files changed** (the `custody: fix CUS-…` commits), **costs** (tokens and
spend), **handoffs** (surveyor → harness → remediator → auditor → ledger,
by actor name on every ledger entry), and **results** (findings N → M,
rulings, chain intact). Two layers deliver it:

1. The demo run is driven through Claude Code inside the app.xo.builders
   workspace, so the Space shows the session, actions, files changed, and
   costs natively.
2. A **custody adapter for xo-space** (submitted as an open-source
   contribution — 8 files, zero core edits, 12/12 tests) makes Custody a
   first-class runtime: the watcher tails `.custody/ledger.jsonl`, sessions
   are runs keyed by the run's hash-chain seal, every ledger action appears
   as a tool event, verdicts appear as `verdict.proven` /
   `verdict.rejected` counts, and the cost column is backed by token
   accounting inside a hash chain — the only agent whose activity feed is
   tamper-evident.
   - xo-space pull request: https://github.com/quirq-ai/xo-space/pull/161
   - GitHub Discussion: [ADD LINK — post the Discussion introducing PR #161]

## Safeguards, permissions, evaluations, failure handling

- **Refusals before work:** dirty tree, default branch, and an
  already-failing test suite are all refused at preflight — a red baseline
  would convict the agent of breakage it never caused.
- **Scope contracts:** files to be written are declared in advance,
  concrete names only (wildcards refused); writes are checked against the
  *resolved* path; `..` and NTFS stream syntax refused outright.
- **Integrity-critical boundary:** the ledger, the auditor, the surveyor,
  and the enforcement machinery itself are refused at the filesystem —
  tests and CI stay writable on purpose so cheating is *caught*, not hidden.
- **One-way model authority:** the remediator proposes, never decides; the
  reviewer can only withhold a doubtful commit, never mint one, never
  override a rejection; an unreachable reviewer is a recorded gap
  (`review.unavailable`), never a silent pass.
- **Tamper-evident record:** hash-chained ledger with a head marker;
  `custody verify` detects edits, deletions, truncation, tail rewriting,
  and marker deletion, offline, exit code 2.
- **Cost honesty:** spend is measured from token accounting; declaring less
  than measured is a REJECTED cheat (`cost-underreport`); an unpriceable
  model is its own finding (`cost-unverifiable`).
- **Key hygiene:** the audited project's suite runs with
  `ANTHROPIC_API_KEY` stripped from its environment.
- **Measured, not asserted:** 256 stdlib-only tests; a ground-truth eval
  (8/8 injected cheats caught, 0/6 clean fixtures flagged — false positives
  fail the eval too); an adversarial trial of seven scripted cheats that
  doubles as a regression suite; CI on Python 3.9–3.13 plus ruff and
  strict mypy.
- **Known limits, stated:** the ledger is unsigned (evidence against silent
  edits, not against an attacker who owns the disk); analysis is syntactic;
  running a target's suite executes its code — sandbox untrusted
  repositories. See [SECURITY.md](SECURITY.md).

## Tools, models, frameworks, runtimes

- **Model:** Claude Opus 5 (`claude-opus-5`) via a ~30-line stdlib
  `urllib` Messages API client — zero runtime dependencies by design.
- **Language/runtime:** Python 3.9–3.13, standard library only.
- **Infrastructure:** git (subprocess, argument lists only), GitHub
  Actions, Quirq managed cloud (app.xo.builders), Claude Code as the
  driving runtime for the tracked demo session.
- **Dev-only tooling:** ruff 0.6.9, mypy 1.11.2 (pinned).

## Setup and testing

```bash
git clone https://github.com/vilka-9999/custody && cd custody
python -m unittest discover -s tests   # 256 tests, stdlib only
python -m custody eval                 # 8/8 cheats caught, 0/6 clean flagged
python -m custody trial                # 7 adversarial attempts, offline, ~2s
python -m custody survey .             # Custody surveys itself: 0 findings
```

To run the full loop, point it at any Python repo on a scratch branch with
a green test suite (it refuses `main`, dirty trees, and red baselines):

```bash
python -m custody harden <repo> --model claude-opus-5 --limit 5
python -m custody verify <repo>        # recompute the hash chain
python -m custody console <repo>       # read-only ledger dashboard, localhost
```

Offline, keyless: add `--offline` — the deterministic remediator fixes a
subset of rules and declines the rest, at $0.
