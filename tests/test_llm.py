"""Tests for cost accounting and response parsing."""

import unittest

from custody.llm import (
    DEFAULT_MODEL,
    PRICING_USD_PER_MTOK,
    LLMError,
    RefusalError,
    Usage,
    _build_reply,
    api_key,
    extract_json,
)


class CostTests(unittest.TestCase):
    """Spend is derived from tokens, never estimated."""

    def test_opus_pricing_is_exact(self) -> None:
        """One million in and one million out prices at the table rate."""
        usage = Usage(DEFAULT_MODEL, input_tokens=1_000_000, output_tokens=1_000_000)
        self.assertAlmostEqual(usage.cost_usd, 30.00, places=4)

    def test_cache_reads_are_cheaper_than_fresh_input(self) -> None:
        """A cached token costs a tenth of an uncached one."""
        fresh = Usage(DEFAULT_MODEL, input_tokens=1_000_000).cost_usd
        cached = Usage(DEFAULT_MODEL, cache_read_input_tokens=1_000_000).cost_usd
        self.assertAlmostEqual(cached, fresh * 0.1, places=4)

    def test_cache_writes_cost_more_than_fresh_input(self) -> None:
        """Writing to cache carries a premium."""
        fresh = Usage(DEFAULT_MODEL, input_tokens=1_000_000).cost_usd
        written = Usage(DEFAULT_MODEL, cache_creation_input_tokens=1_000_000).cost_usd
        self.assertGreater(written, fresh)

    def test_unknown_model_is_marked_unpriced(self) -> None:
        """An unrecognised model reports zero but flags itself."""
        usage = Usage("some-future-model", input_tokens=1_000_000)
        self.assertEqual(usage.cost_usd, 0.0)
        self.assertFalse(usage.priced)

    def test_known_models_are_priced(self) -> None:
        """Every model in the table reports as priced."""
        for model in PRICING_USD_PER_MTOK:
            self.assertTrue(Usage(model).priced)


class ResponseTests(unittest.TestCase):
    """Parsing a response body."""

    def test_text_and_usage_are_extracted(self) -> None:
        """Text blocks and token counts come through."""
        reply = _build_reply(
            {
                "model": DEFAULT_MODEL,
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "hello"}],
                "usage": {"input_tokens": 10, "output_tokens": 20},
            },
            DEFAULT_MODEL,
        )
        self.assertEqual(reply.text, "hello")
        self.assertEqual(reply.usage.input_tokens, 10)
        self.assertGreater(reply.usage.cost_usd, 0)

    def test_thinking_blocks_are_not_treated_as_text(self) -> None:
        """Reasoning blocks never leak into the answer."""
        reply = _build_reply(
            {
                "model": DEFAULT_MODEL, "stop_reason": "end_turn",
                "content": [
                    {"type": "thinking", "thinking": "internal"},
                    {"type": "text", "text": "answer"},
                ],
                "usage": {},
            },
            DEFAULT_MODEL,
        )
        self.assertEqual(reply.text, "answer")

    def test_tool_calls_are_extracted(self) -> None:
        """Tool use blocks become structured calls."""
        reply = _build_reply(
            {
                "model": DEFAULT_MODEL, "stop_reason": "tool_use",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "edit", "input": {"path": "a.py"}}
                ],
                "usage": {},
            },
            DEFAULT_MODEL,
        )
        self.assertEqual(len(reply.tool_calls), 1)
        self.assertEqual(reply.tool_calls[0]["input"]["path"], "a.py")

    def test_refusal_raises_rather_than_returning_empty(self) -> None:
        """A declined request is an error, not an empty answer."""
        with self.assertRaises(RefusalError):
            _build_reply(
                {
                    "model": DEFAULT_MODEL, "stop_reason": "refusal",
                    "stop_details": {"category": "cyber", "explanation": "declined"},
                    "content": [],
                },
                DEFAULT_MODEL,
            )


class KeyTests(unittest.TestCase):
    """Credential resolution."""

    def test_missing_key_raises_clearly(self) -> None:
        """An absent key fails loudly rather than sending an empty header."""
        import os

        saved = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(LLMError):
                api_key()
        finally:
            if saved is not None:
                os.environ["ANTHROPIC_API_KEY"] = saved

    def test_explicit_key_is_preferred(self) -> None:
        """An explicitly supplied key wins."""
        self.assertEqual(api_key("sk-test"), "sk-test")


class JsonTests(unittest.TestCase):
    """Pulling structured output out of prose."""

    def test_object_in_prose_is_found(self) -> None:
        """A JSON object wrapped in text is extracted."""
        self.assertEqual(extract_json('here: {"a": 1} done'), {"a": 1})

    def test_nested_braces_are_balanced(self) -> None:
        """Nesting does not terminate the scan early."""
        self.assertEqual(extract_json('{"a": {"b": 2}}'), {"a": {"b": 2}})

    def test_braces_inside_strings_are_ignored(self) -> None:
        """A brace inside a string literal does not close the object."""
        self.assertEqual(extract_json('{"a": "}"}'), {"a": "}"})

    def test_absent_json_returns_none(self) -> None:
        """Prose with no object yields None rather than a guess."""
        self.assertIsNone(extract_json("no json here"))

    def test_malformed_json_returns_none(self) -> None:
        """Broken JSON is not repaired silently."""
        self.assertIsNone(extract_json('{"a": }'))


if __name__ == "__main__":
    unittest.main()
