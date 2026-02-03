"""Tests for LocalModelProvider."""

import os
import unittest
from unittest.mock import MagicMock, patch

from pydantic import BaseModel

from llm.local_provider import LocalModelProvider, is_local_url


class TestSchema(BaseModel):
    message: str
    count: int


class TestIsLocalUrl(unittest.TestCase):
    """Tests for is_local_url function."""

    def test_localhost(self):
        self.assertTrue(is_local_url("http://localhost:1234/v1"))
        self.assertTrue(is_local_url("http://localhost/v1"))
        self.assertTrue(is_local_url("https://localhost:8080"))

    def test_127_0_0_1(self):
        self.assertTrue(is_local_url("http://127.0.0.1:1234/v1"))
        self.assertTrue(is_local_url("http://127.0.0.1:8080"))

    def test_0_0_0_0(self):
        self.assertTrue(is_local_url("http://0.0.0.0:1234/v1"))

    def test_ipv6_localhost(self):
        self.assertTrue(is_local_url("http://[::1]:1234"))

    def test_remote_urls(self):
        self.assertFalse(is_local_url("https://api.openai.com/v1"))
        self.assertFalse(is_local_url("https://openrouter.ai/api"))

    def test_none_and_empty(self):
        self.assertFalse(is_local_url(None))
        self.assertFalse(is_local_url(""))


class TestLocalModelProviderInit(unittest.TestCase):
    """Tests for LocalModelProvider initialization."""

    @patch.dict(os.environ, {"OPENAI_BASE_URL": "http://localhost:1234", "OPENAI_API_KEY": "test"})
    @patch("llm.local_provider.OpenAI")
    def test_init_with_defaults(self, mock_openai):
        config = {}
        provider = LocalModelProvider(config, "test-model")

        self.assertEqual(provider.temperature, 0.1)
        self.assertEqual(provider.max_tokens, 4096)
        self.assertEqual(provider.repetition_penalty, 1.3)
        self.assertEqual(provider.model_name, "test-model")

    @patch.dict(os.environ, {"OPENAI_BASE_URL": "http://localhost:1234", "OPENAI_API_KEY": "test"})
    @patch("llm.local_provider.OpenAI")
    def test_init_with_config_overrides(self, mock_openai):
        config = {
            "local": {
                "temperature": 0.2,
                "max_tokens": 2048,
                "repetition_penalty": 1.5,
            }
        }
        provider = LocalModelProvider(config, "test-model")

        self.assertEqual(provider.temperature, 0.2)
        self.assertEqual(provider.max_tokens, 2048)
        self.assertEqual(provider.repetition_penalty, 1.5)

    @patch.dict(os.environ, {"OPENAI_BASE_URL": "http://localhost:1234", "OPENAI_API_KEY": "test"})
    @patch("llm.local_provider.OpenAI")
    def test_init_with_parameter_overrides(self, mock_openai):
        config = {"local": {"temperature": 0.2}}  # Config value
        provider = LocalModelProvider(
            config,
            "test-model",
            temperature=0.05,  # Parameter override takes precedence
        )
        self.assertEqual(provider.temperature, 0.05)

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test"}, clear=True)
    @patch("llm.local_provider.OpenAI")
    def test_init_requires_base_url(self, mock_openai):
        # Remove OPENAI_BASE_URL
        if "OPENAI_BASE_URL" in os.environ:
            del os.environ["OPENAI_BASE_URL"]

        config = {}
        with self.assertRaises(ValueError) as ctx:
            LocalModelProvider(config, "test-model")
        self.assertIn("OPENAI_BASE_URL", str(ctx.exception))


class TestLocalModelProviderParse(unittest.TestCase):
    """Tests for LocalModelProvider parse method."""

    def _create_provider(self, mock_openai):
        """Helper to create provider with mocked OpenAI client."""
        config = {}
        with patch.dict(os.environ, {"OPENAI_BASE_URL": "http://localhost:1234", "OPENAI_API_KEY": "test"}):
            provider = LocalModelProvider(config, "test-model")
        return provider

    @patch("llm.local_provider.OpenAI")
    def test_parse_valid_json(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        # Mock successful response with valid JSON
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='{"message": "hello", "count": 42}'))
        ]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        mock_client.chat.completions.create.return_value = mock_response

        provider = self._create_provider(mock_openai_cls)
        result = provider.parse(system="Test", user="Test", schema=TestSchema)

        self.assertEqual(result.message, "hello")
        self.assertEqual(result.count, 42)

    @patch("llm.local_provider.OpenAI")
    def test_parse_json_in_code_block(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        # Mock response with JSON in markdown code block
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content='''Here's the response:
```json
{"message": "extracted", "count": 99}
```'''))
        ]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        mock_client.chat.completions.create.return_value = mock_response

        provider = self._create_provider(mock_openai_cls)
        result = provider.parse(system="Test", user="Test", schema=TestSchema)

        self.assertEqual(result.message, "extracted")
        self.assertEqual(result.count, 99)

    @patch("llm.local_provider.OpenAI")
    def test_parse_repairs_malformed_json(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        # Mock response with repairable JSON (single quotes, trailing comma)
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content="{'message': 'repaired', 'count': 7,}"))
        ]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        mock_client.chat.completions.create.return_value = mock_response

        provider = self._create_provider(mock_openai_cls)
        result = provider.parse(system="Test", user="Test", schema=TestSchema)

        self.assertEqual(result.message, "repaired")
        self.assertEqual(result.count, 7)

    @patch("llm.local_provider.OpenAI")
    def test_parse_retries_on_invalid_json(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        # First call returns garbage, second returns valid JSON
        responses = [
            MagicMock(
                choices=[MagicMock(message=MagicMock(content="not json"))],
                usage=MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            ),
            MagicMock(
                choices=[MagicMock(message=MagicMock(content='{"message": "retry", "count": 2}'))],
                usage=MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            ),
        ]
        mock_client.chat.completions.create.side_effect = responses

        provider = self._create_provider(mock_openai_cls)
        result = provider.parse(system="Test", user="Test", schema=TestSchema)

        self.assertEqual(result.message, "retry")
        self.assertEqual(mock_client.chat.completions.create.call_count, 2)

    @patch("llm.local_provider.OpenAI")
    def test_parse_fails_after_max_attempts(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        # All calls return garbage
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content="garbage garbage garbage"))
        ]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        mock_client.chat.completions.create.return_value = mock_response

        provider = self._create_provider(mock_openai_cls)

        with self.assertRaises(RuntimeError) as ctx:
            provider.parse(system="Test", user="Test", schema=TestSchema)

        self.assertIn("Failed to parse", str(ctx.exception))


class TestLocalModelProviderRaw(unittest.TestCase):
    """Tests for LocalModelProvider raw method."""

    @patch("llm.local_provider.OpenAI")
    def test_raw_returns_text(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Hello, world!"))]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        mock_client.chat.completions.create.return_value = mock_response

        with patch.dict(os.environ, {"OPENAI_BASE_URL": "http://localhost:1234", "OPENAI_API_KEY": "test"}):
            provider = LocalModelProvider({}, "test-model")

        result = provider.raw(system="Test", user="What is 2+2?")
        self.assertEqual(result, "Hello, world!")


class TestLocalModelProviderProperties(unittest.TestCase):
    """Tests for LocalModelProvider properties."""

    @patch("llm.local_provider.OpenAI")
    def test_provider_name(self, mock_openai_cls):
        with patch.dict(os.environ, {"OPENAI_BASE_URL": "http://localhost:1234", "OPENAI_API_KEY": "test"}):
            provider = LocalModelProvider({}, "test-model")
        self.assertEqual(provider.provider_name, "Local")

    @patch("llm.local_provider.OpenAI")
    def test_supports_thinking(self, mock_openai_cls):
        with patch.dict(os.environ, {"OPENAI_BASE_URL": "http://localhost:1234", "OPENAI_API_KEY": "test"}):
            provider = LocalModelProvider({}, "test-model")
        self.assertFalse(provider.supports_thinking)


if __name__ == "__main__":
    unittest.main()
