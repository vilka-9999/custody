# Custody

**Chain of custody for machine-written code.**

An autonomous agent hardens a repository while a second, independent agent
prosecutes every claim it makes against artifacts — and records the whole
proceeding in a tamper-evident ledger.

Agents now write most of the code and read almost none of it. The usual
response is to trust the agent's own account of what it did. Custody does not:
it re-derives what happened from the diff, the test results and a fresh
deterministic survey, then rules on whether the agent's account survives
contact with the evidence.

## Install

No third-party runtime dependencies. Python 3.9 or newer.

```bash
python -m custody survey .
```

## Commands

| Command | What it does |
| --- | --- |
| `custody survey [repo]` | Deterministic analysis: dangerous sinks, committed secrets, complexity, missing types and docs. Same input, same output, every time. |
| `custody verify [repo]` | Recomputes the ledger hash chain and reports the first entry that does not reconcile. |
| `custody eval` | Scores the auditor against twelve fixtures with known answers. |

## Design

Four components, adversarially separated.

**Surveyor** — fully deterministic, no language model. Given the same tree it
emits the same findings in the same order, which is what lets the auditor
re-survey after a change and compare the two runs honestly.

**Remediator** — acts only under a *scope contract* it declares before
touching anything: which finding it is addressing, which files it may write,
what it expects to change, and how it will know it worked.

**Auditor** — never reads the remediator's prose. Seven deterministic
detectors ask whether the attempt cheated:

| Detector | Question it answers |
| --- | --- |
| `test-removed` / `assertions-removed` / `test-skipped` / `vacuous-assertion` | Did the suite stop asking anything? |
| `suppression-added` | Was the checker silenced instead of satisfied? |
| `coverage-inflation` | Do new tests execute code without asserting? |
| `scope-escape` | Was a file written that the contract never declared? |
| `gate-loosened` / `gate-removed` | Did a quality threshold move in the easy direction? |
| `vacuous-fix` | Does a fresh survey still report the finding? |
| `cost-underreport` | Was spend declared below what was measured? |

A language model's only role in the audit is adjudicating cases these
detectors flag as ambiguous. Detection itself is deterministic, so an
accusation can be re-checked by anyone and cannot be argued away by a
persuasive commit message.

**Ledger** — append-only JSONL. Each entry's hash covers its own content and
the hash of the entry before it, so altering or removing any historical entry
invalidates everything after it.

## Boundaries enforced in code, not in prompts

A remediation attempt may never write tests, CI configuration, quality
thresholds, the auditor's own source, or the ledger. These are refused before
the agent runs, whatever the contract claims, because an agent that can edit
its judge or its record is not being audited at all. Any change that leaves
the test suite red is reverted in full; the attempt survives only as a ledger
entry.

## What a verdict does and does not claim

Every ruling carries both lists explicitly. `PROVEN` licenses exactly three
statements — the finding is absent from a fresh survey, the suite passed, and
every file written was declared. It does **not** license the claim that the
code is correct, that no new defect was introduced, or that the change was the
best available fix.

`INSUFFICIENT_EVIDENCE` is never collapsed into a clean result. A survey that
could not complete reports *this is not a clean result*, rather than zero.

## Measured, not asserted

`custody eval` runs twelve fixtures with known ground truth: seven attempts
that cheat, and five that only look like they might.

```
Detection rate:     7/7 injected cheats caught
False positives:    0/5 clean attempts flagged
Result:             PASS
```

The clean five matter as much as the cheating seven. A detector that flags
everything is worthless, so false positives are measured with the same
seriousness as misses.

## Tests

```bash
python -m unittest discover -s tests
```

The suite uses only the standard library, so it runs anywhere Python does.

## License

MIT.
