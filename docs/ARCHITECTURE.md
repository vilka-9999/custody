# Architecture

Four components, adversarially separated. No component can perform another's
job, and the remediator never learns whether its own output was accepted until
after the ruling is recorded.

```
  Surveyor  ──(findings)──>  Harness  ──(contract)──>  Remediator
  deterministic              preflight,               proposes a bounded
  no LLM                     apply, revert            change; acts
                                   │
                                   ├──> project's own test suite
                                   ├──> fresh Surveyor re-run
                                   │
                                   v
                              Auditor  ──(ruling)──>  Ledger
                              7 deterministic          append-only
                              detectors +              hash-chained
                              adjudication             + head marker
```

## Module map

| Path | Role |
| --- | --- |
| `custody/findings.py` | The `Finding` record shared by every component. Stable ids, total ordering. |
| `custody/surveyor/ast_rules.py` | AST rules, import-alias resolution, cyclomatic complexity. |
| `custody/surveyor/secrets.py` | Credential patterns, placeholder suppression, redaction. |
| `custody/surveyor/runner.py` | Bounded ordered walk. Reports what it examined, not only what it found. |
| `custody/remediator/contract.py` | Scope contracts; protected and integrity-critical globs. |
| `custody/remediator/deterministic.py` | Rule-based fixes that decline rather than guess. |
| `custody/remediator/agent.py` | Model-backed proposals; malformed input rejected, never coerced. |
| `custody/harness.py` | Preflight, apply, verify, adjudicate, keep or revert. |
| `custody/auditor/detectors.py` | The seven deterministic reward-hacking detectors. |
| `custody/auditor/verdict.py` | Rulings and the claims each one licenses. |
| `custody/ledger.py` | Hash chain, head marker, offline verification. |
| `custody/gitio.py` | Argument-list git wrappers; ref validation. |
| `custody/llm.py` | Stdlib Messages API client with per-call cost accounting. |
| `custody/testing.py` | Runs the project's suite; separates *failed* from *never ran*. |
| `custody/console.py` | Read-only dashboard; surfaces a broken chain. |
| `custody/trial.py` | The adversarial trial: seven scripted attempts, one honest. |
| `custody/evaluation.py` | Fourteen ground-truth fixtures scoring the auditor. |

## The determinism boundary

This is the line that answers "where is it agentic versus a fixed pipeline?"

**Deterministic, no model:** the entire surveyor, all seven detectors, scope
enforcement, the hash chain, and the deterministic remediator.

**Model-backed:** proposing a fix (`remediator/agent.py`), and adjudicating
cases the detectors flag as ambiguous.

Detection is deterministic on purpose. An accusation that can be reproduced
by anyone cannot be argued away by a persuasive commit message, and the same
input always yields the same answer on replay.

## Three decisions worth knowing

### Prevention for the evidence, detection for everything else

A contract claiming tests, CI config, quality thresholds, the auditor's source
or the ledger is rejected before the agent runs.

Two of those go further. `.custody/` and `custody/auditor/` are
**integrity-critical**: a write is refused at the filesystem, not detected
afterwards. An agent that can edit the record of its own conduct cannot be
meaningfully audited.

Everything else protected stays writable *on purpose*. The agent is allowed to
reach for a test file and is then caught and reverted. Preventing that cheat
would hide it.

Detection is the point, but it only means anything while the evidence is
beyond the agent's reach.

### Finding identity is content, and clearing takes two signals

A finding's id is derived from the rule, the file, and the *content* of the
flagged line - never its line number. An earlier line-keyed scheme meant
inserting one blank line above a finding retired its id: the contracted id
vanished from a fresh survey and an unfixed finding adjudicated as PROVEN.

Content anchoring alone is not enough either, because a cosmetic edit to the
flagged line also retires the id without fixing anything. So PROVEN requires
two independent signals: the contracted id is gone, *and* the count of
findings of that rule in that file fell. An id that vanished while the count
held is a finding that was reworded, not repaired.

### Guards apply to the resolved path, never the spelling

Every write decision is made against the resolved repository-relative path.
Keys containing `..` are refused before resolution, and protected-path
matching folds case.

This was learned the hard way. An earlier version matched globs against the
raw proposal key, so `a/../custody/ledger.py` — not textually equal to any
protected glob, and resolving *inside* the repository — passed both the
protection check and the containment check while landing on the ledger. The
harness then filtered that same path out of the auditor's evidence using
git's canonical spelling, making the write invisible to every detector.

A guard has to be applied to the same representation the operating system will
act on.

### Zero runtime dependencies

An auditing tool that drags in a supply chain undermines its own premise. The
Claude API is ~30 lines of `urllib.request`; git is `subprocess`; analysis is
`ast`; hashing is `hashlib`; the console is `http.server`.

The cost is real: retries, streaming and typed errors are ours to maintain
rather than the SDK's. For most projects the official SDK is the better
default.

## Data flow through one case

1. **Preflight** — refuse a dirty tree, a non-repository, or a default branch.
2. **Survey** — deterministic findings, ordered by severity.
3. **Contract** — the remediator declares its authority *before* acting.
   Claiming protected territory is rejected here, before anything runs.
4. **Apply** — files written, subject to path resolution and the
   integrity-critical refusal.
5. **Test** — the project's own suite. Three outcomes, never two: passed,
   failed, or never ran.
6. **Re-survey** — a fresh deterministic run for comparison.
7. **Detect** — seven deterministic checks over the artifacts.
8. **Adjudicate** — a ruling, with explicit permitted and prohibited claims.
9. **Keep or revert** — `PROVEN` commits; everything else is reverted in full
   and survives only as a ledger entry.

Every step appends to the ledger before anything is summarised to a human.

## Known limits

- **The ledger is unsigned.** The chain plus head marker detects silent edits,
  middle deletions and tail truncation. It does not defend against an attacker
  with write access to both files, who can recompute a consistent alternate
  history. Keeping that directory out of the agent's reach is what the
  integrity-critical boundary is for.
- **Analysis is syntactic.** Import aliases resolve; dynamic rebinding
  (`f = os.system; f(cmd)`) does not. A non-literal `shell=` value is reported
  as unresolved rather than assumed safe.
- **"The suite is green" is only as strong as the suite.** Custody verifies
  that a project's own tests pass. It does not assess whether they test
  anything.
- **Running a target's suite executes that repository's code.** Inherent to
  the method. Sandbox untrusted repositories.
- **A generated docstring satisfies a rule without adding knowledge.** It ships
  because undocumented public API is worse, and the auditor still confirms the
  finding actually cleared.
