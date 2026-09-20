"""The acting agent: proposes a bounded fix for one finding.

The agent is asked for two things at once - the authority it wants and the
change it intends to make - because a contract written after the fact is not
a constraint. What it returns is a proposal, not a decision: the harness
decides whether any of it survives, and the auditor rules on what happened.

Nothing here trusts the model's own account of its work. The cost recorded
against a proposal comes from token accounting, not from anything the model
says about it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from custody.findings import Finding
from custody.harness import Proposal
from custody.llm import DEFAULT_MODEL, LLMError, call, extract_json
from custody.remediator.contract import ScopeContract

MAX_FILE_CHARS = 40000
"""Source longer than this is truncated in the prompt rather than silently cut."""

SYSTEM_PROMPT = """You are a remediation agent operating under a scope contract.

You will be shown one finding in a repository and the source file it sits in.
Propose the smallest change that resolves that finding and nothing else.

Rules you are held to, and which are enforced mechanically:
- You may only write files you declare in allowed_paths.
- You may never write tests, CI configuration, or quality thresholds. Weakening
  verification is treated as a failed attempt, not a fix.
- You may never suppress a checker (# noqa, # type: ignore) in place of fixing
  the cause.
- The project's test suite must still pass. If your change breaks it, the whole
  attempt is reverted.

Return one JSON object and no other text:
{
  "allowed_paths": ["path/to/file.py"],
  "hypothesis": "one sentence on what will fix it and why",
  "verification": "one sentence on how you expect this to be confirmed",
  "files": {"path/to/file.py": "<the complete new contents of the file>"}
}

"files" must contain the entire file, not a diff or a fragment."""


class ProposalError(RuntimeError):
    """Raised when the model's output cannot be read as a proposal."""


def _read_source(repo: Path, rel: str) -> str:
    """Return the contents of ``rel``, truncated with an explicit marker."""
    try:
        text = (repo / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(text) <= MAX_FILE_CHARS:
        return text
    return text[:MAX_FILE_CHARS] + "\n# ... truncated by custody; file exceeds prompt budget\n"


def build_prompt(repo: Path, finding: Finding) -> str:
    """Compose the request for one finding."""
    source = _read_source(repo, finding.path)
    return (
        "Finding %s (%s, %s)\n"
        "Location: %s\n"
        "Message: %s\n"
        "Evidence: %s\n\n"
        "Current contents of %s:\n"
        "```python\n%s\n```\n"
        % (
            finding.id, finding.rule, finding.severity.value,
            finding.location(), finding.message, finding.evidence or "(none)",
            finding.path, source,
        )
    )


def parse_proposal(
    payload: Dict[str, object], finding: Finding, measured_cost: float
) -> Proposal:
    """Turn a decoded model response into a :class:`Proposal`.

    Raises:
        ProposalError: If required fields are missing or the wrong shape. A
            malformed proposal is rejected rather than coerced, because a
            guessed contract is not a declared one.
    """
    paths = payload.get("allowed_paths")
    files = payload.get("files")
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        raise ProposalError("allowed_paths must be a list of strings")
    if not isinstance(files, dict) or not files:
        raise ProposalError("files must be a non-empty object")
    for path, content in files.items():
        if not isinstance(path, str) or not isinstance(content, str):
            raise ProposalError("files must map string paths to string contents")

    contract = ScopeContract(
        finding_id=finding.id,
        allowed_paths=[str(p) for p in paths],
        hypothesis=str(payload.get("hypothesis", "")).strip() or "(none given)",
        verification=str(payload.get("verification", "")).strip() or "(none given)",
    )
    return Proposal(
        contract=contract,
        files={str(k): str(v) for k, v in files.items()},
        declared_cost_usd=measured_cost,
        measured_cost_usd=measured_cost,
    )


def propose(
    repo: Path,
    finding: Finding,
    model: str = DEFAULT_MODEL,
    effort: str = "high",
    key: Optional[str] = None,
) -> Proposal:
    """Ask the model for a bounded fix and return it as a proposal.

    Raises:
        ProposalError: If the model returned nothing usable.
        LLMError: If the request itself failed.
    """
    reply = call(
        prompt=build_prompt(repo, finding),
        system=SYSTEM_PROMPT,
        model=model,
        effort=effort,
        key=key,
    )
    payload = extract_json(reply.text)
    if payload is None:
        raise ProposalError("model returned no JSON object")
    return parse_proposal(payload, finding, reply.usage.cost_usd)


def available(key: Optional[str] = None) -> bool:
    """Return whether an API key is present, without making a request."""
    import os

    return bool(key or os.environ.get("ANTHROPIC_API_KEY"))
