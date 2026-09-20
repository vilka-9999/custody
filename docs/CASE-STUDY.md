# Case study: hardening Bottle

Custody run against a real repository: [bottlepy/bottle](https://github.com/bottlepy/bottle),
a single-file web framework in production use for fifteen years, cloned at
`main` and hardened on a scratch branch with the deterministic remediator
(no model, no key, no network).

## Survey

```
$ custody survey ../bottle
39 files scanned (30 Python); 1457 findings (dependencies 0, quality 1450, security 7)

CRITICAL dangerous-call-pickle-loads   bottle.py:1190   pickle.loads() deserialises arbitrary objects
CRITICAL dangerous-call-pickle-loads   bottle.py:2993   pickle.loads() deserialises arbitrary objects
CRITICAL dangerous-call-eval           bottle.py:3776   eval() executes arbitrary code
CRITICAL dangerous-call-exec           bottle.py:4167   exec() executes arbitrary code
```

The security findings are real: the `pickle.loads` calls sit in cookie
decoding, a genuinely dangerous pattern on untrusted input, and the
`eval`/`exec` calls are the template engine doing what template engines do.
Reporting them is correct; *fixing* them is a semantic decision no
deterministic rule should make - which is exactly how the run treats them.

## Harden

```
$ custody harden ../bottle --offline --limit 45

3 adjudicated, 42 declined, over 45 attempt(s)
findings 1457 -> 1454
PROVEN                 3
REJECTED               0
committed              3
ledger entries         64
ledger recorded        True

$ custody verify ../bottle
chain intact: 64 entries verified
```

Three findings genuinely fixed, each a one-line commit, each PROVEN only
after Bottle's **own 381-test suite passed** on the changed tree and a
fresh survey confirmed the finding gone. Forty-two attempts declined -
`eval` in a template engine, cyclomatic complexity, annotations - because
the deterministic remediator refuses to guess at semantic changes. Declining
is a result: the model-backed remediator (`--model claude-opus-5`) is the
component that takes on the harder findings, under the same contracts and
the same adjudication.

```
$ git log --oneline -3   # in ../bottle
8f7bee1 custody: fix CUS-1EAF0119 (missing-docstring)
e3c474d custody: fix CUS-6775A440 (missing-docstring)
6c830c3 custody: fix CUS-A254F75E (missing-docstring)
```

## What the exercise found in Custody itself

Pointing the tool at a real repository surfaced three defects in the tool,
all fixed with regression tests before this document was written:

1. **`test/` layouts were invisible.** Bottle keeps its suite in `test/`
   (singular); Custody only looked for `tests/` and root-level files, so a
   fifteen-year-old project "had no suite" and every verdict would have been
   INSUFFICIENT_EVIDENCE.
2. **A red baseline convicted the innocent.** Bottle's suite had 9
   pre-existing failures in one environment (line-ending sensitive template
   tests). The harness never measured a baseline, so every attempt would
   have been REJECTED as "the suite failed after the change" - breakage the
   agent never caused. `custody harden` now refuses to start against a suite
   that is already red, the same way it refuses a dirty tree.
3. **Writes were not byte-exact.** On Windows, applying a proposal rewrote
   every LF line ending to CRLF - 4,581 phantom changes drowning the one
   real change in the diff the auditor reads as evidence. Proposals now land
   byte-for-byte on every platform.

That is the project's method working on itself: the honest way to claim a
tool audits real repositories is to run it on one and record what broke.
