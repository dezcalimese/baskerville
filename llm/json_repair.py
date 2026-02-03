"""JSON extraction and repair utilities for local models.

Local models often produce malformed JSON or wrap it in markdown code blocks.
This module provides utilities to extract, repair, and validate JSON output.
"""
from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar('T', bound=BaseModel)


def extract_json(text: str) -> str:
    """
    Extract JSON from text that may contain markdown code blocks or prose.

    Handles (in order of preference):
    - ```json ... ``` code blocks (explicit JSON)
    - Raw JSON (starting with { or [)
    - Generic ``` ... ``` code blocks (as fallback)

    Args:
        text: Raw text that may contain JSON

    Returns:
        Extracted JSON string (may still need repair)
    """
    if not text or not text.strip():
        return ""

    text = text.strip()

    # 1. First try explicit ```json blocks (highest priority)
    json_block_match = re.search(r'```json\s*\n?([\s\S]*?)\n?```', text, re.IGNORECASE)
    if json_block_match:
        return json_block_match.group(1).strip()

    # 2. Try to find raw JSON object or array directly
    # Look for { or [ that might start JSON
    obj_start = text.find('{')
    arr_start = text.find('[')

    if obj_start != -1 or arr_start != -1:
        # Determine which comes first
        if obj_start == -1:
            start = arr_start
        elif arr_start == -1:
            start = obj_start
        else:
            start = min(obj_start, arr_start)

        # Find the matching closing bracket
        bracket_count = 0
        in_string = False
        escape_next = False
        end = start

        for i in range(start, len(text)):
            char = text[i]

            if escape_next:
                escape_next = False
                continue

            if char == '\\' and in_string:
                escape_next = True
                continue

            if char == '"' and not escape_next:
                in_string = not in_string
                continue

            if in_string:
                continue

            if char in '{[':
                bracket_count += 1
            elif char in '}]':
                bracket_count -= 1
                if bracket_count == 0:
                    end = i
                    break

        if bracket_count == 0:
            extracted = text[start:end + 1]
            # Verify it looks like JSON (not Python dict syntax in prose)
            if '"' in extracted or "'" in extracted:
                return extracted

        # Brackets not balanced - try repair_json later
        if bracket_count > 0:
            return text[start:]

    # 3. Fallback: try generic code blocks (but skip known non-JSON languages)
    generic_block_match = re.search(r'```(\w*)\s*\n?([\s\S]*?)\n?```', text)
    if generic_block_match:
        lang = generic_block_match.group(1).lower()
        content = generic_block_match.group(2).strip()
        # Skip blocks that are clearly not JSON
        if lang not in ('python', 'py', 'javascript', 'js', 'typescript', 'ts',
                        'solidity', 'sol', 'rust', 'go', 'java', 'cpp', 'c',
                        'bash', 'sh', 'shell', 'sql', 'html', 'css', 'yaml', 'yml'):
            # Check if content looks like JSON
            if content.startswith('{') or content.startswith('['):
                return content

    # 4. No JSON found - return original text for repair attempt
    return text


def repair_json(text: str) -> str:
    """
    Attempt to repair common JSON issues from local models.

    Repairs:
    - Trailing commas in arrays/objects
    - Single quotes -> double quotes
    - Unquoted keys
    - Truncated arrays/objects (closes brackets)
    - JavaScript-style comments
    - NaN/Infinity -> null

    Args:
        text: Potentially malformed JSON string

    Returns:
        Repaired JSON string (may still be invalid)
    """
    if not text or not text.strip():
        return "{}"

    text = text.strip()

    # Remove JavaScript-style comments
    # Single-line comments
    text = re.sub(r'//[^\n]*', '', text)
    # Multi-line comments
    text = re.sub(r'/\*[\s\S]*?\*/', '', text)

    # Replace NaN and Infinity with null
    text = re.sub(r'\bNaN\b', 'null', text)
    text = re.sub(r'\bInfinity\b', 'null', text)
    text = re.sub(r'-Infinity\b', 'null', text)

    # Replace Python-style None, True, False
    text = re.sub(r'\bNone\b', 'null', text)
    text = re.sub(r'\bTrue\b', 'true', text)
    text = re.sub(r'\bFalse\b', 'false', text)

    # Try to fix single quotes to double quotes (carefully)
    # Only do this outside of already-double-quoted strings
    text = _fix_quotes(text)

    # Fix unquoted keys: { key: "value" } -> { "key": "value" }
    text = re.sub(
        r'([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:',
        r'\1"\2":',
        text
    )

    # Remove trailing commas before } or ]
    text = re.sub(r',(\s*[}\]])', r'\1', text)

    # Try to close truncated structures
    text = _close_brackets(text)

    return text


def _fix_quotes(text: str) -> str:
    """Fix single quotes to double quotes outside of already-quoted strings."""
    result = []
    i = 0
    in_double_string = False
    in_single_string = False

    while i < len(text):
        char = text[i]

        # Handle escape sequences
        if i > 0 and text[i - 1] == '\\':
            result.append(char)
            i += 1
            continue

        if char == '"' and not in_single_string:
            in_double_string = not in_double_string
            result.append(char)
        elif char == "'" and not in_double_string:
            if in_single_string:
                in_single_string = False
                result.append('"')
            else:
                in_single_string = True
                result.append('"')
        else:
            result.append(char)

        i += 1

    return ''.join(result)


def _close_brackets(text: str) -> str:
    """Close any unclosed brackets in JSON text."""
    # Count open brackets (ignoring those in strings)
    open_braces = 0
    open_brackets = 0
    in_string = False
    escape_next = False

    for char in text:
        if escape_next:
            escape_next = False
            continue

        if char == '\\' and in_string:
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == '{':
            open_braces += 1
        elif char == '}':
            open_braces -= 1
        elif char == '[':
            open_brackets += 1
        elif char == ']':
            open_brackets -= 1

    # Close any unclosed brackets
    # First close arrays, then objects (inner to outer typically)
    text = text.rstrip()

    # Remove trailing comma if present
    if text.endswith(','):
        text = text[:-1]

    # Close brackets
    text += ']' * open_brackets
    text += '}' * open_braces

    return text


def validate_and_parse(text: str, schema: type[T]) -> tuple[T | None, str | None]:
    """
    Extract, repair, and validate JSON against a Pydantic schema.

    Args:
        text: Raw text from model
        schema: Pydantic model class to validate against

    Returns:
        Tuple of (parsed_object, error_message)
        If successful, error_message is None
        If failed, parsed_object is None
    """
    # Extract JSON from any wrapper
    json_text = extract_json(text)

    # First try parsing as-is
    try:
        return schema.model_validate_json(json_text), None
    except (json.JSONDecodeError, ValidationError):
        pass

    # Try with repairs
    repaired = repair_json(json_text)
    try:
        return schema.model_validate_json(repaired), None
    except json.JSONDecodeError as e:
        return None, f"JSON decode error: {e}"
    except ValidationError as e:
        return None, f"Validation error: {e}"


def get_schema_prompt(schema: type[BaseModel]) -> str:
    """
    Generate a prompt-friendly description of a JSON schema.

    Args:
        schema: Pydantic model class

    Returns:
        String describing the expected JSON format
    """
    try:
        json_schema = schema.model_json_schema()
    except Exception:
        try:
            json_schema = schema.schema()
        except Exception:
            return ""

    # Convert to a compact but readable format
    schema_str = json.dumps(json_schema, indent=2)

    return f"""You MUST respond with valid JSON matching this exact schema:
{schema_str}

CRITICAL RULES:
1. Output ONLY the JSON object - nothing else
2. Do NOT include any thinking, reasoning, or explanation
3. Do NOT wrap in markdown code blocks
4. Do NOT prefix with "Here is" or similar phrases
5. Start your response with {{ and end with }}
6. Use double quotes for all strings and keys
7. No trailing commas
8. All required fields must be present"""


def detect_repetition(text: str, threshold: int = 50) -> bool:
    """
    Detect if the model output contains repetitive garbage.

    Common failure mode: "F, F, F, F, F, ..." or "}, }, }, }"

    Args:
        text: Model output text
        threshold: Number of repeated patterns to consider as garbage

    Returns:
        True if repetition detected
    """
    if not text or len(text) < threshold:
        return False

    # Check for repeated short patterns (specific garbage patterns)
    patterns = [
        r'([A-Z],\s*){' + str(threshold) + r',}',  # "F, F, F, F"
        r'(\},\s*){' + str(threshold) + r',}',  # "}, }, }, }"
        r'(\],\s*){' + str(threshold) + r',}',  # "], ], ], ]"
        r'(\.\s*){' + str(threshold) + r',}',  # ". . . . ."
        r'(null,?\s*){' + str(threshold) + r',}',  # "null, null, null"
    ]

    for pattern in patterns:
        if re.search(pattern, text):
            return True

    # Check for the same word repeated many times (e.g., "the the the the")
    words = text.split()
    if len(words) >= threshold:
        # Check for runs of identical consecutive words
        run_length = 1
        for i in range(1, len(words)):
            if words[i] == words[i - 1]:
                run_length += 1
                if run_length >= threshold:
                    return True
            else:
                run_length = 1

    return False
