"""
Base formatter for platform submissions.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..finding import Finding, Severity


@dataclass
class FormattedFinding:
    """A formatted finding ready for submission."""
    title: str
    body: str
    severity: str
    category: str | None = None
    labels: list[str] | None = None
    metadata: dict[str, Any] | None = None

    def to_markdown(self) -> str:
        """Get full markdown representation."""
        return f"# {self.title}\n\n{self.body}"


class BaseFormatter(ABC):
    """Base class for platform formatters."""

    platform: str = "unknown"

    # Severity mapping for the platform
    severity_map: dict[Severity, str] = {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFORMATIONAL: "Informational",
        Severity.GAS: "Gas",
    }

    @abstractmethod
    def format_finding(self, finding: Finding) -> FormattedFinding:
        """Format a single finding for the platform."""
        pass

    def format_findings(self, findings: list[Finding]) -> list[FormattedFinding]:
        """Format multiple findings."""
        return [self.format_finding(f) for f in findings]

    def format_code_block(self, code: str, language: str = "solidity") -> str:
        """Format a code block."""
        return f"```{language}\n{code}\n```"

    def format_location(self, finding: Finding) -> str:
        """Format the finding location."""
        parts = []
        if finding.file_path:
            parts.append(finding.file_path)
        if finding.line_start:
            if finding.line_end and finding.line_end != finding.line_start:
                parts.append(f"L{finding.line_start}-L{finding.line_end}")
            else:
                parts.append(f"L{finding.line_start}")
        return ":".join(parts) if parts else "Unknown location"

    def severity_label(self, severity: Severity) -> str:
        """Get platform-specific severity label."""
        return self.severity_map.get(severity, "Unknown")

    def escape_markdown(self, text: str) -> str:
        """Escape special markdown characters."""
        chars_to_escape = ['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!']
        for char in chars_to_escape:
            text = text.replace(char, f'\\{char}')
        return text
