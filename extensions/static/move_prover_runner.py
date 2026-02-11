"""
Move Prover wrapper for Sui/Aptos Move programs.

Runs `sui move prove` and parses verification output into Hound hypothesis format.
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class MoveProverFinding:
    """A single finding from the Move Prover."""

    property: str
    status: str  # e.g. "error", "failure", "timeout"
    file_path: str = ""
    line: int = 0
    message: str = ""

    def to_hypothesis(self) -> dict[str, Any]:
        """Convert to Hound hypothesis format."""
        # Map failure types to severity
        severity = self._map_severity()

        # Map status to confidence
        confidence_map = {
            "error": 0.9,
            "failure": 0.85,
            "timeout": 0.5,
        }

        description = self.message or f"Move Prover verification failure: {self.property}"
        if self.file_path:
            description += f"\n\nLocation: {self.file_path}"
            if self.line:
                description += f":{self.line}"

        return {
            "title": f"Move Prover: {self.property}",
            "description": description,
            "vulnerability_type": f"move-prover-{self.property}",
            "severity": severity,
            "confidence": confidence_map.get(self.status, 0.7),
            "status": "proposed",
            "node_refs": [],
            "evidence": [],
            "properties": {
                "source_tool": "move-prover",
                "source_files": [self.file_path] if self.file_path else [],
                "affected_lines": [self.line] if self.line else [],
                "prover_status": self.status,
                "prover_property": self.property,
            },
        }

    def _map_severity(self) -> str:
        """Map prover failure type to Hound severity."""
        property_lower = self.property.lower()

        # Arithmetic/overflow properties are high severity
        if any(kw in property_lower for kw in [
            "overflow", "underflow", "arithmetic", "abort",
            "invariant", "assert",
        ]):
            return "high"

        # Access control and resource properties
        if any(kw in property_lower for kw in [
            "access", "permission", "capability", "signer",
            "resource", "borrow",
        ]):
            return "high"

        # Specification violations
        if any(kw in property_lower for kw in [
            "ensures", "requires", "modifies",
        ]):
            return "medium"

        # Timeout suggests complexity but unknown severity
        if self.status == "timeout":
            return "medium"

        return "medium"


class MoveProverRunner:
    """Runs the Move Prover via the Sui CLI and parses its output."""

    def __init__(self, timeout: int = 300):
        """Initialize Move Prover runner.

        Args:
            timeout: Maximum seconds to wait for the prover
        """
        self.timeout = timeout

    def is_available(self) -> tuple[bool, str]:
        """Check if the Sui CLI (and Move Prover) is installed.

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

    def run(self, project_path: Path) -> tuple[list[MoveProverFinding], dict]:
        """Run the Move Prover on a project.

        Args:
            project_path: Path to Move project

        Returns:
            Tuple of (findings, metadata)
        """
        metadata: dict[str, Any] = {
            "tool": "move-prover",
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
            cmd = ["sui", "move", "prove"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=project_root,
            )

            # The prover outputs to both stdout and stderr
            # Verification failures appear in stderr
            output = result.stdout + "\n" + result.stderr

            metadata["success"] = True

            # Parse verification output
            findings = self._parse_output(output)

            return findings, metadata

        except subprocess.TimeoutExpired:
            metadata["error"] = f"Move Prover timed out after {self.timeout}s"
            return [], metadata
        except Exception as e:
            metadata["error"] = f"Move Prover error: {e}"
            return [], metadata

    def _parse_output(self, output: str) -> list[MoveProverFinding]:
        """Parse Move Prover output for verification failures.

        The prover outputs errors in formats like:
            error: [<property>] at <file>:<line>: <message>
            error: verification failed for <property> at <file>:<line>
            error[E<code>]: <message>
              --> <file>:<line>:<col>

        Args:
            output: Combined stdout and stderr from the prover

        Returns:
            List of parsed findings
        """
        findings = []
        lines = output.splitlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Pattern 1: error: [property] at file:line: message
            match = re.match(
                r"error:\s*\[([^\]]+)\]\s*(?:at\s+)?([^:]+):(\d+)(?::\d+)?:\s*(.*)",
                line,
            )
            if match:
                finding = MoveProverFinding(
                    property=match.group(1).strip(),
                    status="error",
                    file_path=match.group(2).strip(),
                    line=int(match.group(3)),
                    message=match.group(4).strip(),
                )
                findings.append(finding)
                i += 1
                continue

            # Pattern 2: error: verification failed for <property>
            match = re.match(
                r"error:\s*verification\s+failed\s+(?:for\s+)?(\S+)",
                line,
                re.IGNORECASE,
            )
            if match:
                property_name = match.group(1).strip()
                file_path = ""
                line_num = 0

                # Check next line for location info
                if i + 1 < len(lines):
                    loc_match = re.match(
                        r"\s*(?:-->|at)\s*([^:]+):(\d+)",
                        lines[i + 1],
                    )
                    if loc_match:
                        file_path = loc_match.group(1).strip()
                        line_num = int(loc_match.group(2))
                        i += 1

                finding = MoveProverFinding(
                    property=property_name,
                    status="failure",
                    file_path=file_path,
                    line=line_num,
                    message=line,
                )
                findings.append(finding)
                i += 1
                continue

            # Pattern 3: error[E<code>]: <message> with --> file:line:col on next line
            match = re.match(r"error\[E\d+\]:\s*(.*)", line)
            if match:
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

                # Derive a property name from the message
                property_name = self._extract_property_from_message(message)

                finding = MoveProverFinding(
                    property=property_name,
                    status="error",
                    file_path=file_path,
                    line=line_num,
                    message=message,
                )
                findings.append(finding)
                i += 1
                continue

            # Pattern 4: timeout during verification
            if "timeout" in line.lower() and "prover" in line.lower():
                finding = MoveProverFinding(
                    property="verification-timeout",
                    status="timeout",
                    message=line,
                )
                findings.append(finding)
                i += 1
                continue

            i += 1

        return findings

    def _extract_property_from_message(self, message: str) -> str:
        """Extract a meaningful property name from an error message.

        Args:
            message: Error message text

        Returns:
            A normalized property name
        """
        msg_lower = message.lower()

        if "abort" in msg_lower:
            return "abort-condition"
        if "overflow" in msg_lower or "underflow" in msg_lower:
            return "arithmetic-overflow"
        if "borrow" in msg_lower:
            return "borrow-violation"
        if "resource" in msg_lower:
            return "resource-violation"
        if "type" in msg_lower:
            return "type-error"
        if "invariant" in msg_lower:
            return "invariant-violation"
        if "ensures" in msg_lower:
            return "postcondition-failure"
        if "requires" in msg_lower:
            return "precondition-failure"

        # Fallback: sanitize the message as a property name
        sanitized = re.sub(r"[^a-z0-9]+", "-", msg_lower).strip("-")
        return sanitized[:50] if sanitized else "unknown"
