"""
Custom AST pattern matchers for Solidity.

Detects patterns that Slither/Aderyn may miss, feeding into
Hound's hypothesis system.

NOTE: This is a stub for future implementation. The pattern matching
will use Slither's AST or a custom parser to find Solidity-specific
vulnerability patterns.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ASTPattern:
    """A pattern to match in Solidity AST."""

    name: str
    description: str
    severity: str
    pattern_type: str  # function, modifier, state_variable, etc.
    match_criteria: dict  # Pattern-specific matching rules


@dataclass
class ASTMatch:
    """A match found by an AST pattern."""

    pattern: ASTPattern
    file_path: str
    line_number: int
    code_snippet: str
    context: dict  # Additional match context

    def to_hypothesis(self) -> dict[str, Any]:
        """Convert to Hound hypothesis format."""
        return {
            "title": f"AST Pattern: {self.pattern.name}",
            "description": f"{self.pattern.description}\n\nFound at {self.file_path}:{self.line_number}",
            "vulnerability_type": f"ast-pattern-{self.pattern.name}",
            "severity": self.pattern.severity,
            "confidence": 0.6,  # Lower confidence for pattern matches
            "status": "proposed",
            "node_refs": [],
            "evidence": [],
            "properties": {
                "source_tool": "ast_patterns",
                "source_files": [self.file_path],
                "affected_lines": [self.line_number],
                "pattern_type": self.pattern.pattern_type,
            },
        }


class ASTPatternMatcher:
    """Matches custom patterns against Solidity AST.

    Future implementation will support patterns like:
    - Unchecked external calls in loops
    - Missing access control on sensitive functions
    - Unsafe delegatecall patterns
    - Price oracle manipulation risks
    - Flash loan attack vectors
    - Storage collision in upgradeable contracts
    """

    # Built-in patterns (to be expanded)
    DEFAULT_PATTERNS: list[ASTPattern] = [
        # Placeholder patterns - actual implementation would use AST parsing
    ]

    def __init__(self, patterns: list[ASTPattern] | None = None):
        """Initialize pattern matcher.

        Args:
            patterns: Custom patterns to use (in addition to defaults)
        """
        self.patterns = list(self.DEFAULT_PATTERNS)
        if patterns:
            self.patterns.extend(patterns)

    def is_available(self) -> tuple[bool, str]:
        """Check if pattern matching is available.

        Currently a stub - always returns True.
        Full implementation would check for Slither AST support.
        """
        return True, "stub-1.0.0"

    def run(self, project_path: Path) -> tuple[list[ASTMatch], dict]:
        """Run pattern matching on a project.

        Args:
            project_path: Path to Solidity project

        Returns:
            Tuple of (matches, metadata)

        NOTE: Currently a stub that returns empty results.
        Full implementation would:
        1. Use Slither to parse AST
        2. Walk AST nodes matching patterns
        3. Return matches with source locations
        """
        metadata = {
            "tool": "ast_patterns",
            "version": "stub-1.0.0",
            "success": True,
            "patterns_checked": len(self.patterns),
            "note": "AST pattern matching not yet implemented",
        }

        # Stub: return empty results
        matches: list[ASTMatch] = []

        return matches, metadata


# Example patterns for future implementation
EXAMPLE_PATTERNS = [
    ASTPattern(
        name="unchecked-call-in-loop",
        description="External call inside a loop without gas limit",
        severity="medium",
        pattern_type="function",
        match_criteria={
            "contains": ["for", "while"],
            "has_external_call": True,
            "no_gas_limit": True,
        },
    ),
    ASTPattern(
        name="missing-zero-address-check",
        description="Address parameter used without zero-address validation",
        severity="low",
        pattern_type="function",
        match_criteria={
            "has_address_param": True,
            "no_zero_check": True,
            "is_state_modifying": True,
        },
    ),
    ASTPattern(
        name="unsafe-delegatecall",
        description="Delegatecall with user-controlled target",
        severity="high",
        pattern_type="function",
        match_criteria={
            "contains": ["delegatecall"],
            "target_is_param": True,
        },
    ),
]
