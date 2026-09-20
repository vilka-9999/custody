"""A minimal Claude Messages API client built on the standard library.

Custody declares no runtime third-party dependencies, so this module speaks
HTTP to the Messages API directly rather than importing the official SDK. That
is a deliberate trade: the SDK is the better default for most projects, but an
auditing tool that drags in a supply chain undermines its own premise. The
cost is that retries, streaming and typed errors are ours to maintain.

Every call returns its own token accounting. The auditor compares what an
agent *declared* it spent against what was *measured* here, so under-reporting
is detectable rather than trusted.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"

DEFAULT_MODEL = "claude-opus-5"
"""Opus 5 is the default. Choosing a cheaper model is the operator's call."""

DEFAULT_MAX_TOKENS = 16000
"""Keeps non-streaming responses inside the default HTTP timeout."""

DEFAULT_TIMEOUT = 600
DEFAULT_RETRIES = 3

PRICING_USD_PER_MTOK: Dict[str, Dict[str, float]] = {
    "claude-opus-5": {"input": 5.00, "output": 25.00},
    "claude-sonnet-5": {"input": 2.00, "output": 10.00},
    "claude-haiku-4-5": {"input": 1.00, "output": 5.00},
}
"""First-party API rates. Unknown models price at zero and say so."""

CACHE_WRITE_MULTIPLIER = 1.25
CACHE_READ_MULTIPLIER = 0.1

RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504})


class LLMError(RuntimeError):
    """Raised when a request cannot be completed."""


class RefusalError(LLMError):
    """Raised when the model declines the request on safety grounds."""

    def __init__(self, category: Optional[str], explanation: str) -> None:
        """Record the structured refusal details the API returned."""
        super().__init__("model refused (%s): %s" % (category or "unspecified", explanation))
        self.category = category
        self.explanation = explanation


@dataclass(frozen=True)
class Usage:
    """Token accounting and derived spend for one call."""

    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    @property
    def priced(self) -> bool:
        """Return whether this model has a known rate."""
        return self.model in PRICING_USD_PER_MTOK

    @property
    def cost_usd(self) -> float:
        """Return spend in dollars, or 0.0 when the model is unpriced.

        An unpriced model yields zero rather than a guess. Callers that care
        about the difference check :attr:`priced` first, so an unknown rate is
        never silently reported as free.
        """
        rates = PRICING_USD_PER_MTOK.get(self.model)
        if rates is None:
            return 0.0
        total = (
            self.input_tokens * rates["input"]
            + self.cache_creation_input_tokens * rates["input"] * CACHE_WRITE_MULTIPLIER
            + self.cache_read_input_tokens * rates["input"] * CACHE_READ_MULTIPLIER
            + self.output_tokens * rates["output"]
        )
        return round(total / 1_000_000, 6)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable view for the ledger."""
        return {
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
            "cost_usd": self.cost_usd,
            "priced": self.priced,
        }


@dataclass(frozen=True)
class Reply:
    """One model response, decomposed for callers."""

    text: str
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    stop_reason: str = ""
    usage: Usage = field(default_factory=lambda: Usage(DEFAULT_MODEL))
    raw_content: List[Dict[str, Any]] = field(default_factory=list)


def api_key(explicit: Optional[str] = None) -> str:
    """Return the API key, preferring an explicit value over the environment."""
    key = explicit or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise LLMError(
            "no API key: set ANTHROPIC_API_KEY, or pass one explicitly"
        )
    return key


def _decompose(content: Sequence[Dict[str, Any]]) -> tuple:
    """Split response content blocks into text and tool calls."""
    text_parts: List[str] = []
    tool_calls: List[Dict[str, Any]] = []
    for block in content:
        kind = block.get("type")
        if kind == "text":
            text_parts.append(block.get("text", ""))
        elif kind == "tool_use":
            tool_calls.append(
                {"id": block.get("id", ""), "name": block.get("name", ""),
                 "input": block.get("input", {})}
            )
    return "\n".join(text_parts).strip(), tool_calls


def _post(payload: Dict[str, Any], key: str, timeout: int) -> Dict[str, Any]:
    """Send one request and return the decoded JSON body."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        API_URL,
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "x-api-key": key,
            "anthropic-version": API_VERSION,
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def call(
    prompt: str,
    system: str = "",
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    effort: str = "high",
    tools: Optional[List[Dict[str, Any]]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    key: Optional[str] = None,
) -> Reply:
    """Send one message and return the decomposed reply.

    Thinking is left adaptive, which is the default on Opus 5. ``budget_tokens``
    is deliberately never sent: it is rejected with a 400 on current models.

    Raises:
        RefusalError: If the model declined on safety grounds.
        LLMError: If the request failed after exhausting retries.
    """
    payload: Dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": effort},
    }
    if system:
        payload["system"] = system
    if tools:
        payload["tools"] = tools

    resolved = api_key(key)
    last_error = ""

    for attempt in range(retries):
        try:
            data = _post(payload, resolved, timeout)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            last_error = "HTTP %d: %s" % (exc.code, detail)
            if exc.code not in RETRYABLE_STATUS:
                raise LLMError(last_error) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = "connection error: %s" % exc
        except json.JSONDecodeError as exc:
            raise LLMError("malformed response body") from exc
        else:
            return _build_reply(data, model)

        if attempt < retries - 1:
            time.sleep(min(2.0 ** attempt, 30.0))

    raise LLMError("request failed after %d attempts: %s" % (retries, last_error))


def _build_reply(data: Dict[str, Any], model: str) -> Reply:
    """Turn a decoded response body into a :class:`Reply`."""
    stop_reason = data.get("stop_reason", "")
    if stop_reason == "refusal":
        details = data.get("stop_details") or {}
        raise RefusalError(details.get("category"), details.get("explanation", ""))

    raw_usage = data.get("usage") or {}
    usage = Usage(
        model=data.get("model", model),
        input_tokens=int(raw_usage.get("input_tokens", 0)),
        output_tokens=int(raw_usage.get("output_tokens", 0)),
        cache_creation_input_tokens=int(raw_usage.get("cache_creation_input_tokens", 0) or 0),
        cache_read_input_tokens=int(raw_usage.get("cache_read_input_tokens", 0) or 0),
    )
    content = data.get("content") or []
    text, tool_calls = _decompose(content)
    return Reply(
        text=text, tool_calls=tool_calls, stop_reason=stop_reason,
        usage=usage, raw_content=list(content),
    )


def _scan_object_end(text: str, start: int) -> int:
    """Return the index just past the JSON object beginning at ``start``.

    Brace counting is string-aware: a brace inside a string literal does not
    open or close the object, and a backslash escape does not end the string.
    Returns -1 when the object never closes.
    """
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return -1


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Pull the first JSON object out of a model response.

    Tool inputs and structured replies are always parsed as JSON rather than
    matched as strings, because escaping in model output varies between
    models. Malformed JSON yields ``None`` rather than a repaired guess.
    """
    start = text.find("{")
    if start < 0:
        return None
    end = _scan_object_end(text, start)
    if end < 0:
        return None
    try:
        parsed = json.loads(text[start:end])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
