# Contributing

## Running everything

```bash
python -m unittest discover -s tests   # 114 tests, stdlib only
python -m custody eval                 # auditor vs. 12 ground-truth fixtures
python -m custody trial                # 7 adversarial attempts, offline
python -m custody survey .             # Custody surveys itself
```

All four must pass. CI runs them on Python 3.9 through 3.13.

## The one rule

**No runtime third-party dependencies.** An auditing tool that drags in a
supply chain undermines its own premise. `pyproject.toml` declares an empty
`dependencies` list and it stays empty. Dev tooling (`ruff`, `mypy`) is pinned
under `optional-dependencies.dev`.

If you reach for a library, the answer is the standard library or a smaller
feature.

## Adding a detector

A detector answers one question about the artifacts an attempt left behind,
and answers it **deterministically** — no model call. Same input, same output,
every time, so an accusation can be re-checked by anyone and cannot be argued
away by a persuasive commit message.

1. Add the function to `custody/auditor/detectors.py`, taking a `DiffContext`
   and returning `List[Detection]`.
2. Register it in `DETECTORS`.
3. Add **two** fixtures to `custody/evaluation.py`: one attempt that cheats
   this way, and one that superficially resembles it but does not.

The second fixture is not optional. A detector that flags everything is
worthless, so false positives are measured with the same seriousness as
misses, and `custody eval` fails on either.

## Adding a deterministic fixer

Fixers live in `custody/remediator/deterministic.py` and are pure functions
from source text to source text.

**Decline rather than guess.** `fix_shell_true` refuses when the first
argument is a command string, because rewriting it into a list is a semantic
change. Returning `None` is a real answer and a good one. A fixer that clears
a rule without fixing the problem is worse than no fixer — the auditor will
catch it as `vacuous-fix`, but you have spent a cycle producing a false
result.

## Style

Type annotations and docstrings on everything public; `custody survey .`
enforces both and must report zero findings. Cyclomatic complexity ceiling is
10. Comments explain *why*, never *what*.
