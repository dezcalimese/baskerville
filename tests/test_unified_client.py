"""
Tests for UnifiedLLMClient provider selection and raw passthrough.
"""

import os
import unittest
from unittest.mock import patch

from llm.unified_client import UnifiedLLMClient


class DummyProvider:
    provider_name = "dummy"
    supports_thinking = False
    def __init__(self, **kwargs):
        self.init_kwargs = kwargs
    def raw(self, *, system: str, user: str) -> str:
        return f"SYS:{system}|USER:{user}"


class DummyLocalProvider:
    provider_name = "dummy_local"
    supports_thinking = False
    def __init__(self, **kwargs):
        self.init_kwargs = kwargs
    def raw(self, *, system: str, user: str) -> str:
        return f"LOCAL|SYS:{system}|USER:{user}"


class TestUnifiedClient(unittest.TestCase):
    def test_selects_openai_provider(self):
        cfg = {"models": {"reporting": {"provider": "openai", "model": "x"}}}
        with patch('llm.unified_client.OpenAIProvider', DummyProvider):
            uc = UnifiedLLMClient(cfg, profile="reporting")
            self.assertEqual(uc.provider.provider_name, "dummy")
            out = uc.raw(system="S", user="U")
            self.assertIn("SYS:S|USER:U", out)

    def test_selects_local_provider_for_localhost(self):
        """Test that localhost URLs route to LocalModelProvider."""
        cfg = {"models": {"reporting": {"provider": "openai", "model": "x"}}}
        with patch.dict(os.environ, {"OPENAI_BASE_URL": "http://localhost:1234/v1"}):
            with patch('llm.unified_client.LocalModelProvider', DummyLocalProvider):
                with patch('llm.unified_client.is_local_url', return_value=True):
                    uc = UnifiedLLMClient(cfg, profile="reporting")
                    self.assertEqual(uc.provider.provider_name, "dummy_local")

    def test_selects_local_provider_for_127_0_0_1(self):
        """Test that 127.0.0.1 URLs route to LocalModelProvider."""
        cfg = {"models": {"reporting": {"provider": "openai", "model": "x"}}}
        with patch.dict(os.environ, {"OPENAI_BASE_URL": "http://127.0.0.1:8080/v1"}):
            with patch('llm.unified_client.LocalModelProvider', DummyLocalProvider):
                with patch('llm.unified_client.is_local_url', return_value=True):
                    uc = UnifiedLLMClient(cfg, profile="reporting")
                    self.assertEqual(uc.provider.provider_name, "dummy_local")

    def test_selects_openai_for_remote_url(self):
        """Test that remote URLs still use OpenAIProvider."""
        cfg = {"models": {"reporting": {"provider": "openai", "model": "x"}}}
        with patch.dict(os.environ, {"OPENAI_BASE_URL": "https://api.openai.com/v1"}):
            with patch('llm.unified_client.OpenAIProvider', DummyProvider):
                with patch('llm.unified_client.is_local_url', return_value=False):
                    uc = UnifiedLLMClient(cfg, profile="reporting")
                    self.assertEqual(uc.provider.provider_name, "dummy")
