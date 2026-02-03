"""Tests for JSON repair utilities used by local model provider."""

import unittest

from pydantic import BaseModel

from llm.json_repair import (
    detect_repetition,
    extract_json,
    get_schema_prompt,
    repair_json,
    validate_and_parse,
)


class SimpleSchema(BaseModel):
    name: str
    value: int


class NestedSchema(BaseModel):
    items: list[str]
    metadata: dict[str, str]


class TestExtractJson(unittest.TestCase):
    """Tests for extract_json function."""

    def test_extracts_from_markdown_code_block(self):
        text = '''Here's the response:
```json
{"name": "test", "value": 42}
```
That's the data.'''
        result = extract_json(text)
        self.assertEqual(result, '{"name": "test", "value": 42}')

    def test_extracts_from_code_block_no_lang(self):
        text = '''Response:
```
{"items": ["a", "b"]}
```'''
        result = extract_json(text)
        self.assertEqual(result, '{"items": ["a", "b"]}')

    def test_extracts_raw_json_object(self):
        text = 'Some prose {"name": "test"} more prose'
        result = extract_json(text)
        self.assertEqual(result, '{"name": "test"}')

    def test_extracts_raw_json_array(self):
        text = 'Here: ["a", "b", "c"]'
        result = extract_json(text)
        self.assertEqual(result, '["a", "b", "c"]')

    def test_handles_nested_braces(self):
        text = '{"outer": {"inner": "value"}}'
        result = extract_json(text)
        self.assertEqual(result, '{"outer": {"inner": "value"}}')

    def test_returns_empty_for_empty_input(self):
        self.assertEqual(extract_json(""), "")
        self.assertEqual(extract_json("   "), "")

    def test_prefers_code_block_over_inline(self):
        text = '''Look at {"inline": 1}
```json
{"block": 2}
```'''
        result = extract_json(text)
        self.assertEqual(result, '{"block": 2}')


class TestRepairJson(unittest.TestCase):
    """Tests for repair_json function."""

    def test_removes_trailing_commas_in_array(self):
        text = '["a", "b", "c",]'
        result = repair_json(text)
        self.assertEqual(result, '["a", "b", "c"]')

    def test_removes_trailing_commas_in_object(self):
        text = '{"name": "test", "value": 1,}'
        result = repair_json(text)
        self.assertEqual(result, '{"name": "test", "value": 1}')

    def test_converts_single_quotes(self):
        text = "{'name': 'test'}"
        result = repair_json(text)
        self.assertEqual(result, '{"name": "test"}')

    def test_quotes_unquoted_keys(self):
        text = '{name: "test", value: 42}'
        result = repair_json(text)
        self.assertIn('"name":', result)
        self.assertIn('"value":', result)

    def test_replaces_python_none(self):
        text = '{"value": None}'
        result = repair_json(text)
        self.assertIn("null", result)

    def test_replaces_python_true_false(self):
        text = '{"a": True, "b": False}'
        result = repair_json(text)
        self.assertIn('"a": true', result)
        self.assertIn('"b": false', result)

    def test_replaces_nan_infinity(self):
        text = '{"a": NaN, "b": Infinity, "c": -Infinity}'
        result = repair_json(text)
        self.assertEqual(result.count("null"), 3)

    def test_removes_single_line_comments(self):
        text = '{"name": "test" // this is a comment\n}'
        result = repair_json(text)
        self.assertNotIn("//", result)

    def test_removes_multi_line_comments(self):
        text = '{"name": /* comment */ "test"}'
        result = repair_json(text)
        self.assertNotIn("/*", result)

    def test_closes_unclosed_braces(self):
        text = '{"name": "test"'
        result = repair_json(text)
        self.assertTrue(result.endswith('}'))

    def test_closes_unclosed_brackets(self):
        text = '["a", "b"'
        result = repair_json(text)
        self.assertTrue(result.endswith(']'))

    def test_returns_empty_object_for_empty_input(self):
        self.assertEqual(repair_json(""), "{}")
        self.assertEqual(repair_json("   "), "{}")


class TestValidateAndParse(unittest.TestCase):
    """Tests for validate_and_parse function."""

    def test_parses_valid_json(self):
        text = '{"name": "test", "value": 42}'
        result, error = validate_and_parse(text, SimpleSchema)
        self.assertIsNone(error)
        self.assertEqual(result.name, "test")
        self.assertEqual(result.value, 42)

    def test_extracts_and_parses_from_markdown(self):
        text = '''```json
{"name": "test", "value": 123}
```'''
        result, error = validate_and_parse(text, SimpleSchema)
        self.assertIsNone(error)
        self.assertEqual(result.name, "test")

    def test_repairs_and_parses(self):
        text = "{'name': 'test', 'value': 42,}"  # Single quotes, trailing comma
        result, error = validate_and_parse(text, SimpleSchema)
        self.assertIsNone(error)
        self.assertEqual(result.name, "test")

    def test_returns_error_for_invalid_json(self):
        text = "not json at all"
        result, error = validate_and_parse(text, SimpleSchema)
        self.assertIsNone(result)
        self.assertIsNotNone(error)

    def test_returns_error_for_schema_mismatch(self):
        text = '{"name": "test"}'  # Missing required 'value' field
        result, error = validate_and_parse(text, SimpleSchema)
        self.assertIsNone(result)
        self.assertIn("error", error.lower())


class TestDetectRepetition(unittest.TestCase):
    """Tests for detect_repetition function."""

    def test_detects_letter_repetition(self):
        text = "F, " * 100
        self.assertTrue(detect_repetition(text))

    def test_detects_brace_repetition(self):
        text = "}, " * 100
        self.assertTrue(detect_repetition(text))

    def test_detects_word_repetition(self):
        text = "hello " * 100
        self.assertTrue(detect_repetition(text))

    def test_detects_null_repetition(self):
        text = "null, " * 100
        self.assertTrue(detect_repetition(text))

    def test_no_false_positive_for_normal_text(self):
        text = '{"name": "test", "items": ["a", "b", "c"]}'
        self.assertFalse(detect_repetition(text))

    def test_no_false_positive_for_prose(self):
        # Normal prose should NOT trigger repetition detection
        text = "The user wants me to analyze a simple function. Let me think about this carefully."
        self.assertFalse(detect_repetition(text))

    def test_handles_short_text(self):
        text = "short"
        self.assertFalse(detect_repetition(text))

    def test_handles_empty_text(self):
        self.assertFalse(detect_repetition(""))
        self.assertFalse(detect_repetition(None))


class TestGetSchemaPrompt(unittest.TestCase):
    """Tests for get_schema_prompt function."""

    def test_generates_prompt_with_schema(self):
        prompt = get_schema_prompt(SimpleSchema)
        self.assertIn("name", prompt)
        self.assertIn("value", prompt)
        self.assertIn("JSON", prompt)

    def test_includes_critical_rules(self):
        prompt = get_schema_prompt(SimpleSchema)
        self.assertIn("double quotes", prompt.lower())
        self.assertIn("trailing commas", prompt.lower())


if __name__ == "__main__":
    unittest.main()
