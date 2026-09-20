"""Model adjudication of ambiguous detections - a one-way ratchet.

Detection is deterministic and stays that way. But the detectors emit two
kinds of signal: CRITICAL detections, which reject an attempt outright, and
advisory ones (HIGH, MEDIUM), which record suspicion without deciding the
case. An attempt can therefore clear every deterministic gate - finding gone,
suite green, scope respected - while carrying advisory detections, such as a
suppression comment added in a file the contract legitimately covered. That
is the one genuinely ambiguous state in the audit, and it is the language
model's only role here: to read the evidence and decide whether the advisory
concerns are substantive enough to withhold the commit.

The power granted is deliberately asymmetric. The reviewer can withhold a
PROVEN commit; it can never mint one, never override a rejection, never
silence a detection, and never touch the ruling's claim lists - every
statement PROVEN licenses remains deterministically true whether or not the
commit is kept. A model may add caution to the audit; it may not remove any.
When the model cannot be reached, or returns something unreadable, the
deterministic ruling stands and the gap is recorded - an unavailable reviewer
is missing evidence, not an acquittal and not a conviction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional

from custody.auditor.detectors import DiffContext
from custody.auditor.verdict import Judgment, Ruling
from custody.llm import DEFAULT_MODEL, LLMError, call, extract_json

MAX_EXCERPT_CHARS = 4000
"""Per-file bound on the diff evidence quoted to the reviewer."""

SYSTEM_PROMPT = """You are the reviewing half of an adversarial code auditor.

A remediation attempt has cleared every deterministic gate: the contracted
finding is gone from a fresh survey, the project's test suite passed, and
every file written was declared in advance. However, deterministic detectors
raised the advisory concerns listed below. Your job is to judge whether those
concerns are substantive enough that the change should not be committed.

Rules you are held to, and which are enforced mechanically:
- You may only add caution. Objecting withholds the commit; approving merely
  lets the deterministic ruling proceed. You cannot override a rejection,
  remove a detection, or alter what the ruling claims.
- Judge only the evidence shown. Do not speculate about intent.

Return one JSON object and no other text:
{
  "objects": true or false,
  "concern": "one sentence: the substantive problem, or why the signals are benign here"
}"""


@dataclass(frozen=True)
class SecondOpinion:
    """The reviewer's judgment on an ambiguous, otherwise-PROVEN attempt.

    Attributes:
        objects: Whether the commit should be withheld.
        concern: One sentence of reasoning, recorded verbatim in the ledger.
        model: The model that produced the opinion.
        cost_usd: Measured spend for the review call.
        tokens_in: Prompt tokens consumed.
        tokens_out: Completion tokens produced.
    """

    objects: bool
    concern: str
    model: str = ""
    cost_usd: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view for the ledger."""
        return {
            "objects": self.objects,
            "concern": self.concern,
            "model": self.model,
            "cost_usd": self.cost_usd,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
        }


ReviewFn = Callable[[DiffContext, Judgment], Optional[SecondOpinion]]
"""A reviewer: evidence and ruling in, an opinion or ``None`` out.

``None`` means the review could not be completed. The caller records that
and lets the deterministic ruling stand - fail-safe, never fail-silent.
"""


def needs_review(judgment: Judgment) -> bool:
    """Return whether an attempt sits in the one ambiguous state.

    Only a PROVEN ruling that carries advisory detections is ambiguous. A
    rejection is already decided, a clean PROVEN has nothing to weigh, and
    NOT_OBSERVED or INSUFFICIENT_EVIDENCE commits nothing that a reviewer
    could withhold.
    """
    return judgment.ruling is Ruling.PROVEN and bool(judgment.detections)


def build_review_prompt(ctx: DiffContext, judgment: Judgment) -> str:
    """Compose the evidence bundle the reviewer sees.

    Everything quoted here is an artifact - the contract, the detections,
    and bounded before/after excerpts of the changed files. The remediator's
    prose is deliberately absent: the reviewer weighs evidence, not argument.
    """
    lines = [
        "Deterministic ruling: PROVEN (finding cleared, suite green, scope respected)",
        "",
        "Contract:",
        json.dumps(ctx.contract.to_dict(), indent=2, sort_keys=True),
        "",
        "Advisory detections:",
        json.dumps([d.to_dict() for d in judgment.detections], indent=2, sort_keys=True),
        "",
    ]
    for path in sorted(set(ctx.changed)):
        before = ctx.before.get(path, "")[:MAX_EXCERPT_CHARS]
        after = ctx.after.get(path, "")[:MAX_EXCERPT_CHARS]
        lines.extend([
            f"--- {path} (before) ---", before or "(absent)",
            f"--- {path} (after) ---", after or "(deleted)", "",
        ])
    return "\n".join(lines)


def parse_opinion(payload: dict[str, object] | None) -> SecondOpinion | None:
    """Turn a decoded model response into an opinion, or ``None``.

    A malformed response is not coerced into a verdict in either direction:
    guessing "objects" would let noise block honest work, and guessing
    "approves" would let noise wave concerns through.
    """
    if payload is None:
        return None
    objects = payload.get("objects")
    if not isinstance(objects, bool):
        return None
    concern = str(payload.get("concern", "")).strip() or "(no reason given)"
    return SecondOpinion(objects=objects, concern=concern)


def review_with_model(
    ctx: DiffContext,
    judgment: Judgment,
    model: str = DEFAULT_MODEL,
    key: str | None = None,
) -> SecondOpinion | None:
    """Ask the model to adjudicate the advisory detections.

    Returns ``None`` when the request fails or the reply is unreadable; the
    caller records the gap and the deterministic ruling stands.
    """
    try:
        reply = call(
            prompt=build_review_prompt(ctx, judgment),
            system=SYSTEM_PROMPT,
            model=model,
            key=key,
        )
    except LLMError:
        return None
    opinion = parse_opinion(extract_json(reply.text))
    if opinion is None:
        return None
    return SecondOpinion(
        objects=opinion.objects,
        concern=opinion.concern,
        model=reply.usage.model,
        cost_usd=reply.usage.cost_usd,
        tokens_in=reply.usage.input_tokens,
        tokens_out=reply.usage.output_tokens,
    )
