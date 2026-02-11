"""
Sui Move lint wrapper for Move smart contracts.

Runs `sui move build --lint` and parses lint warnings into Hound hypothesis format.
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SuiMoveLintFinding:
    """A single lint finding from sui move build --lint."""

    lint_id: str
    message: str
    file_path: str = ""
    line: int = 0
    severity: str = "Low"  # High, Medium, Low

    def to_hypothesis(self) -> dict[str, Any]:
        """Convert to Hound hypothesis format."""
        severity_map = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
        }

        confidence_map = {
            "High": 0.85,
            "Medium": 0.7,
            "Low": 0.6,
        }

        description = self.message
        if self.file_path:
            description += f"\n\nLocation: {self.file_path}"
            if self.line:
                description += f":{self.line}"

        return {
            "title": f"Move Lint: {self.lint_id}",
            "description": description,
            "vulnerability_type": f"move-lint-{self.lint_id}",
            "severity": severity_map.get(self.severity, "low"),
            "confidence": confidence_map.get(self.severity, 0.6),
            "status": "proposed",
            "node_refs": [],
            "evidence": [],
            "properties": {
                "source_tool": "sui-move-lint",
                "source_files": [self.file_path] if self.file_path else [],
                "affected_lines": [self.line] if self.line else [],
                "lint_id": self.lint_id,
                "lint_severity": self.severity,
            },
        }


# Map known lint IDs / warning patterns to severity
_LINT_SEVERITY_MAP: dict[str, str] = {
    "unnecessary_while_loop": "Low",
    "unused_variable": "Low",
    "unused_function": "Low",
    "unused_const": "Low",
    "unused_mut_ref": "Low",
    "unused_type_parameter": "Low",
    "dead_code": "Low",
    "self_transfer": "Medium",
    "share_owned": "Medium",
    "custom_state_change": "Medium",
    "freeze_wrapped": "Medium",
    "collection_equality": "Medium",
    "coin_field": "Medium",
    "public_transfer": "Medium",
    "missing_key": "High",
    "object_equality": "Medium",
}


class SuiMoveLintRunner:
    """Runs sui move build --lint and parses lint warnings."""

    def __init__(self, timeout: int = 120):
        """Initialize Sui Move lint runner.

        Args:
            timeout: Maximum seconds to wait for the lint run
        """
        self.timeout = timeout

    def is_available(self) -> tuple[bool, str]:
        """Check if the Sui CLI is installed.

        Returns:
            Tuple of (available, version_or_error)
        """
        import shutil

        if not shutil.which("sui"):
            return False, "sui CLI not found in PATH"

        try:
            result = subprocess.run(
                ["sui", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or result.stderr.strip()
                return True, version
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "timeout checking sui version"
        except Exception as e:
            return False, str(e)

    def _find_project_root(self, path: Path) -> Path:
        """Find the Move project root by looking for Move.toml.

        Args:
            path: Starting path to search from

        Returns:
            Project root path (falls back to input path if not found)
        """
        if path.is_file():
            path = path.parent

        config_files = ["Move.toml", "Sui.toml"]

        current = path.resolve()
        for _ in range(10):
            for config in config_files:
                if (current / config).exists():
                    return current
            parent = current.parent
            if parent == current:
                break
            current = parent

        return path if path.is_dir() else path.parent

    def run(self, project_path: Path) -> tuple[list[SuiMoveLintFinding], dict]:
        """Run sui move build --lint on a project.

        Args:
            project_path: Path to Move project

        Returns:
            Tuple of (findings, metadata)
        """
        metadata: dict[str, Any] = {
            "tool": "sui-move-lint",
            "version": None,
            "success": False,
            "error": None,
        }

        # Check availability
        available, version = self.is_available()
        if not available:
            metadata["error"] = f"Sui CLI not available: {version}"
            return [], metadata

        metadata["version"] = version

        project_root = self._find_project_root(project_path)

        try:
            cmd = ["sui", "move", "build", "--lint"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=project_root,
            )

            # Lint warnings appear in stderr (and sometimes stdout)
            output = result.stdout + "\n" + result.stderr

            metadata["success"] = True

            # Parse lint warnings
            findings = self._parse_output(output)

            return findings, metadata

        except subprocess.TimeoutExpired:
            metadata["error"] = f"Sui Move lint timed out after {self.timeout}s"
            return [], metadata
        except Exception as e:
            metadata["error"] = f"Sui Move lint error: {e}"
            return [], metadata

    def _parse_output(self, output: str) -> list[SuiMoveLintFinding]:
        """Parse sui move build --lint output for warnings.

        Sui Move lint outputs warnings in formats like:
            warning[W01001]: <lint_name>
              --> <file>:<line>:<col>
              |
            <line_num> | <code>
              |   ^^^^ <message>

            warning: <message>
              --> <file>:<line>:<col>

        Args:
            output: Combined stdout and stderr

        Returns:
            List of parsed findings
        """
        findings = []
        lines = output.splitlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Pattern 1: warning[W<code>]: <lint_name>
            match = re.match(r"warning\[W(\d+)\]:\s*(.*)", line)
            if match:
                warning_code = match.group(1).strip()
                lint_name = match.group(2).strip()
                file_path = ""
                line_num = 0
                message = lint_name

                # Look for --> location on the next line
                if i + 1 < len(lines):
                    loc_match = re.match(
                        r"\s*-->\s*([^:]+):(\d+)(?::\d+)?",
                        lines[i + 1],
                    )
                    if loc_match:
                        file_path = loc_match.group(1).strip()
                        line_num = int(loc_match.group(2))
                        i += 1

                # Try to capture additional context from subsequent lines
                # Look for the ^^^^ message line
                j = i + 1
                while j < len(lines) and j < i + 6:
                    ctx_line = lines[j].strip()
                    caret_match = re.match(r"\|\s*\^+\s*(.*)", ctx_line)
                    if caret_match and caret_match.group(1):
                        message = f"{lint_name}: {caret_match.group(1).strip()}"
                        break
                    # Stop if we hit another warning or error
                    if re.match(r"(warning|error)", ctx_line):
                        break
                    j += 1

                lint_id = self._normalize_lint_id(lint_name)
                severity = _LINT_SEVERITY_MAP.get(lint_id, "Low")

                finding = SuiMoveLintFinding(
                    lint_id=lint_id,
                    message=message,
                    file_path=file_path,
                    line=line_num,
                    severity=severity,
                )
                findings.append(finding)
                i += 1
                continue

            # Pattern 2: warning: <message> (no code)
            match = re.match(r"warning:\s+(.+)", line)
            if match and not line.startswith("warning["):
                message = match.group(1).strip()
                file_path = ""
                line_num = 0

                # Look for --> location on the next line
                if i + 1 < len(lines):
                    loc_match = re.match(
                        r"\s*-->\s*([^:]+):(\d+)(?::\d+)?",
                        lines[i + 1],
                    )
                    if loc_match:
                        file_path = loc_match.group(1).strip()
                        line_num = int(loc_match.group(2))
                        i += 1

                lint_id = self._normalize_lint_id(message)
                severity = _LINT_SEVERITY_MAP.get(lint_id, "Low")

                finding = SuiMoveLintFinding(
                    lint_id=lint_id,
                    message=message,
                    file_path=file_path,
                    line=line_num,
                    severity=severity,
                )
                findings.append(finding)
                i += 1
                continue

            i += 1

        return findings

    def _normalize_lint_id(self, name: str) -> str:
        """Normalize a lint name to a consistent ID format.

        Converts names like "Self Transfer" or "self_transfer" to "self_transfer".

        Args:
            name: Raw lint name from output

        Returns:
            Normalized lint ID
        """
        # Take only the first part if there's a colon (e.g., "lint_name: details")
        base = name.split(":")[0].strip()

        # Convert to snake_case
        normalized = re.sub(r"[^a-zA-Z0-9]+", "_", base).strip("_").lower()

        return normalized
