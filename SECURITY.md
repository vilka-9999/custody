# Security

## What Custody does to a repository

Custody writes files, runs the project's test suite, and makes git commits. It
is not a passive analyser. Read this before pointing it at anything you care
about.

### Refusals before any work begins

`custody harden` will not start if:

- the target is not a git repository;
- the working tree has uncommitted changes (Custody's own `.custody/` ledger
  excepted, because merely surveying a repository must not make it ineligible);
- the checked-out branch is `main`, `master`, `trunk`, or `develop`. Override
  with `--allow-default-branch` only if you mean it.

### What an agent may never write

A remediation contract claiming any of these is rejected before the agent
runs: tests, `.github/`, `pyproject.toml`, `setup.cfg`, `tox.ini`, the
auditor's own source, and the ledger.

Two of those are enforced more strictly. `.custody/` and `custody/auditor/`
are **integrity-critical**: a write is refused at the filesystem, not merely
detected afterwards. An agent that can edit the record of its own conduct
cannot be meaningfully audited.

Everything else protected stays writable on purpose. The agent is allowed to
reach for a test file and is then caught and reverted — preventing the cheat
would hide it.

### Execution of untrusted code

Custody runs the target project's test suite as a subprocess. **That executes
code from the repository you point it at.** If you do not trust the
repository, do not run `custody harden` against it outside a sandbox. This is
inherent to the method: "the suite is green" is only evidence if the suite
actually ran.

Custody itself never executes model output. A proposal is written to disk as
data and verified by the project's own suite.

### Subprocess and input handling

- Every git invocation passes an argument list. No shell is involved anywhere.
- Write decisions are made against the resolved repository-relative path.
  Keys containing `..` are refused before resolution; protected-path matching
  is case-insensitive, so a case variant cannot reach the same file on a
  case-insensitive filesystem. A colon anywhere in a key is refused: on NTFS
  it names an alternate data stream attached to another file.
- A contract may only declare concrete file names, never patterns. `**`
  matches no protected glob as a string yet covers every later write, which
  would leave scope-escape unable to fire.
- Refs and branch names are validated against `^[A-Za-z0-9._/\-]{1,255}$`,
  reject `..`, and reject a leading `-` so they cannot be read as options.
- Proposed paths resolving outside the repository are refused, independently
  of contract validation.
- Every subprocess has a timeout: 120s for git, 600s for a test suite.
- The target's test suite runs with `ANTHROPIC_API_KEY` removed from its
  environment. The suite executes code the remediator just wrote, before
  adjudication; it has no business reading Custody's own secret.

### Credentials

The only secret Custody handles is `ANTHROPIC_API_KEY`, read from the
environment and sent to `api.anthropic.com`. It is never written to the
ledger, the console, or any commit. The surveyor's secret scanner redacts
matches before recording them.

The console binds to `127.0.0.1`, is read-only, and refuses any request
whose Host header is not a loopback name, so a DNS-rebinding page cannot
read the ledger through the loopback bind. Do not expose it.

### Known limits

- **The ledger is unsigned.** The hash chain plus head marker detects silent
  edits, middle deletions, tail truncation, tail rewriting (the marker records
  the final entry's seal, not only a count), and marker deletion (a ledger
  with entries but no marker is reported as suspect, not intact). It does not
  defend against an attacker with write access to both the ledger and its head
  marker, who can recompute a consistent alternate history. Protecting that
  directory from the agent under audit is what the integrity-critical boundary
  is for.
- **Analysis is syntactic.** Rules resolve import aliases but not dynamic
  rebinding (`f = os.system; f(cmd)`). A non-literal `shell=` value is
  reported as unresolved rather than assumed safe, but the surveyor cannot
  prove what a runtime value will be.
- **"The suite is green" is only as strong as the suite.** Custody verifies
  that a project's own tests pass; it does not assess whether they test
  anything.

## Reporting a vulnerability

Open an issue describing the problem and how to reproduce it. If it concerns
an agent escaping its declared scope, include the contract and the diff.
