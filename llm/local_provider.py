"""Local model provider for LM Studio and similar OpenAI-compatible servers.

Local models lack server-side JSON schema enforcement, so this provider:
1. Uses low temperature (0.1) for deterministic output
2. Embeds JSON schema in the prompt
3. Extracts JSON from markdown code blocks
4. Repairs common JSON issues
5. Retries with error feedback on validation failure
"""
from __future__ import annotations

import os
import random
import time
from typing import Any, TypeVar

from openai import OpenAI
from pydantic import BaseModel

from .base_provider import BaseLLMProvider
from .json_repair import (
    detect_repetition,
    get_schema_prompt,
    validate_and_parse,
)

T = TypeVar('T', bound=BaseModel)


class LocalModelProvider(BaseLLMProvider):
    """
    Provider for local models (LM Studio, Ollama, text-generation-webui, etc).

    Extends OpenAI API compatibility with robust client-side JSON handling
    since local servers typically don't support structured output features.
    """

    # Default settings optimized for local model JSON generation
    DEFAULT_TEMPERATURE = 0.1  # Low temp for deterministic output
    DEFAULT_MAX_TOKENS = 4096  # Prevent runaway generation
    DEFAULT_REPETITION_PENALTY = 1.3  # Discourage repetitive garbage
    MAX_PARSE_ATTEMPTS = 3  # Retries for JSON parsing

    def __init__(
        self,
        config: dict[str, Any],
        model_name: str,
        timeout: int = 120,
        retries: int = 3,
        backoff_min: float = 2.0,
        backoff_max: float = 8.0,
        temperature: float | None = None,
        max_tokens: int | None = None,
        repetition_penalty: float | None = None,
        **kwargs
    ):
        """
        Initialize local model provider.

        Args:
            config: Full configuration dictionary
            model_name: Name of the model to use
            timeout: Request timeout in seconds
            retries: Number of API-level retries
            backoff_min: Minimum backoff time between retries
            backoff_max: Maximum backoff time between retries
            temperature: Override default temperature (0.1)
            max_tokens: Override default max tokens (4096)
            repetition_penalty: Override default repetition penalty (1.3)
        """
        self.config = config
        self.model_name = model_name
        self.timeout = timeout
        self.retries = retries
        self.backoff_min = backoff_min
        self.backoff_max = backoff_max
        self._last_token_usage = None

        # Local model configuration
        local_cfg = config.get("local", {}) if isinstance(config, dict) else {}
        self.temperature = temperature or local_cfg.get("temperature", self.DEFAULT_TEMPERATURE)
        self.max_tokens = max_tokens or local_cfg.get("max_tokens", self.DEFAULT_MAX_TOKENS)
        self.repetition_penalty = repetition_penalty or local_cfg.get(
            "repetition_penalty", self.DEFAULT_REPETITION_PENALTY
        )

        # Verbose logging
        logging_cfg = config.get("logging", {}) if isinstance(config, dict) else {}
        env_verbose = os.environ.get("HOUND_LLM_VERBOSE", "").lower() in {"1", "true", "yes", "on"}
        self.verbose = bool(logging_cfg.get("llm_verbose", False) or env_verbose)

        # API key (local servers usually accept anything)
        api_key_env = config.get("openai", {}).get("api_key_env", "OPENAI_API_KEY")
        api_key = os.environ.get(api_key_env) or "local-model"

        # Get base URL - must be set for local models
        raw_base_url = os.environ.get("OPENAI_BASE_URL") or config.get("openai", {}).get("base_url")
        if not raw_base_url:
            raise ValueError("OPENAI_BASE_URL must be set for local models")

        base_url = raw_base_url.rstrip("/")
        if not base_url.endswith("/v1"):
            base_url = base_url + "/v1"

        self.base_url = base_url
        self.client = OpenAI(api_key=api_key, base_url=base_url)

        if self.verbose:
            print(f"[Local Provider] Using base_url: {base_url}")
            print(f"[Local Provider] Temperature: {self.temperature}, Max tokens: {self.max_tokens}")

    def parse(self, *, system: str, user: str, schema: type[T], reasoning_effort: str | None = None) -> T:
        """
        Make a structured call with robust JSON handling.

        Uses multiple strategies to get valid JSON:
        1. First try with schema embedded in prompt
        2. On failure, retry with error feedback
        3. Apply JSON extraction and repair
        4. Validate against Pydantic schema

        Args:
            system: System prompt
            user: User prompt
            schema: Pydantic model class for structured output
            reasoning_effort: Ignored (not supported by local models)

        Returns:
            Instance of schema with parsed data

        Raises:
            RuntimeError: If JSON parsing fails after all attempts
        """
        # Build enhanced prompt with schema instructions
        schema_prompt = get_schema_prompt(schema)
        enhanced_system = f"{system}\n\n{schema_prompt}"

        last_error: str | None = None
        last_output: str | None = None

        for attempt in range(self.MAX_PARSE_ATTEMPTS):
            # Build messages
            messages = [{"role": "system", "content": enhanced_system}]

            # On retry, add error feedback to help model correct
            if attempt > 0 and last_error:
                error_guidance = self._build_error_feedback(last_error, last_output, schema)
                messages.append({
                    "role": "user",
                    "content": f"{user}\n\n{error_guidance}"
                })
            else:
                messages.append({"role": "user", "content": user})

            if self.verbose:
                print(f"\n[Local Provider] Parse attempt {attempt + 1}/{self.MAX_PARSE_ATTEMPTS}")
                print(f"  Model: {self.model_name}")
                print(f"  Schema: {schema.__name__}")

            # Make API call with retries
            raw_output = self._call_api(messages)

            if self.verbose:
                output_preview = raw_output[:200] + "..." if len(raw_output) > 200 else raw_output
                print(f"  Raw output: {output_preview}")

            # Check for repetition garbage
            if detect_repetition(raw_output):
                last_error = "Model produced repetitive garbage output. Please provide structured JSON."
                last_output = raw_output[:500]
                if self.verbose:
                    print("  Detected repetitive garbage, retrying...")
                continue

            # Try to extract and validate JSON
            parsed, error = validate_and_parse(raw_output, schema)
            if parsed is not None:
                if self.verbose:
                    print("  Successfully parsed JSON")
                return parsed

            last_error = error
            last_output = raw_output[:1000]
            if self.verbose:
                print(f"  Parse error: {error}")

        # All attempts failed
        error_msg = f"Failed to parse valid JSON after {self.MAX_PARSE_ATTEMPTS} attempts"
        if last_error:
            error_msg += f": {last_error}"
        if last_output:
            error_msg += f"\nLast output sample: {last_output[:500]}"

        raise RuntimeError(error_msg)

    def _build_error_feedback(
        self,
        error: str,
        last_output: str | None,
        schema: type[BaseModel]
    ) -> str:
        """Build error feedback message to help model correct its output."""
        feedback = [
            "IMPORTANT: Your previous response was not valid JSON.",
            f"Error: {error}",
        ]

        if last_output:
            # Show a sample of what went wrong
            sample = last_output[:300]
            feedback.append(f"Your output started with: {sample}")

        feedback.extend([
            "",
            "Please output ONLY valid JSON with no markdown, no code blocks, no explanations.",
            "Start your response with { and end with }",
        ])

        return "\n".join(feedback)

    def _call_api(self, messages: list[dict]) -> str:
        """
        Make API call with retries and handle response.

        Args:
            messages: Chat messages to send

        Returns:
            Raw text content from response

        Raises:
            RuntimeError: If API call fails after all retries
        """
        last_err = None

        for attempt in range(self.retries):
            try:
                # Build request parameters
                params: dict[str, Any] = {
                    "model": self.model_name,
                    "messages": messages,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "timeout": self.timeout,
                }

                # Try to add repetition penalty via extra_body
                # Some servers support this, others ignore it
                try:
                    params["extra_body"] = {
                        "repetition_penalty": self.repetition_penalty
                    }
                except Exception:
                    pass

                completion = self.client.chat.completions.create(**params)

                # Track token usage
                if hasattr(completion, 'usage') and completion.usage:
                    self._last_token_usage = {
                        'input_tokens': completion.usage.prompt_tokens or 0,
                        'output_tokens': completion.usage.completion_tokens or 0,
                        'total_tokens': completion.usage.total_tokens or 0
                    }

                content = completion.choices[0].message.content
                return content or ""

            except Exception as e:
                last_err = e
                if self.verbose:
                    print(f"  API error: {e}")
                if attempt < self.retries - 1:
                    sleep_time = random.uniform(self.backoff_min, self.backoff_max)
                    if self.verbose:
                        print(f"  Retrying after {sleep_time:.2f}s...")
                    time.sleep(sleep_time)

        raise RuntimeError(f"Local model API call failed after {self.retries} attempts: {last_err}")

    def raw(self, *, system: str, user: str, reasoning_effort: str | None = None) -> str:
        """
        Make a plain text call.

        Args:
            system: System prompt
            user: User prompt
            reasoning_effort: Ignored (not supported by local models)

        Returns:
            Raw text response
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ]

        last_err = None
        for attempt in range(self.retries):
            try:
                # For raw calls, use slightly higher temperature for creativity
                params: dict[str, Any] = {
                    "model": self.model_name,
                    "messages": messages,
                    "temperature": 0.7,  # Higher temp for non-JSON tasks
                    "max_tokens": self.max_tokens,
                    "timeout": self.timeout,
                }

                completion = self.client.chat.completions.create(**params)

                # Track token usage
                if hasattr(completion, 'usage') and completion.usage:
                    self._last_token_usage = {
                        'input_tokens': completion.usage.prompt_tokens or 0,
                        'output_tokens': completion.usage.completion_tokens or 0,
                        'total_tokens': completion.usage.total_tokens or 0
                    }

                return completion.choices[0].message.content or ""

            except Exception as e:
                last_err = e
                if attempt < self.retries - 1:
                    sleep_time = random.uniform(self.backoff_min, self.backoff_max)
                    time.sleep(sleep_time)

        raise RuntimeError(f"Local model raw call failed after {self.retries} attempts: {last_err}")

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "Local"

    @property
    def supports_thinking(self) -> bool:
        """Local models don't support thinking mode."""
        return False

    def get_last_token_usage(self) -> dict[str, int] | None:
        """Return token usage from the last call if available."""
        return self._last_token_usage


def is_local_url(url: str | None) -> bool:
    """
    Check if a URL points to a local server.

    Args:
        url: URL to check

    Returns:
        True if URL is localhost or 127.0.0.1
    """
    if not url:
        return False

    url_lower = url.lower()
    return any(host in url_lower for host in [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "[::1]",  # IPv6 localhost
    ])
