"""
Soteria static analyzer wrapper for Solana/Anchor programs.

Runs Soteria and parses text output into Hound hypothesis format.
"""

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SoteriaFinding:
    """A single finding from Soteria."""

    detector: str
    impact: str  # High, Medium, Low
    confidence: str  # High, Medium, Low
    description: str
    file_path: str = ""
    lines: list[int] = field(default_factory=list)

    def to_hypothesis(self) -> dict[str, Any]:
        """Convert to Hound hypothesis format."""
        # Map Soteria impact to Hound severity
        severity_map = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
        }

        # Map confidence to numeric value
        confidence_map = {
            "High": 0.9,
            "Medium": 0.7,
            "Low": 0.5,
        }

        # Build affected code info
        affected_code = ""
        if self.file_path:
            affected_code = self.file_path
            if self.lines:
                affected_code += f":{self.lines[0]}"

        return {
            "title": f"Soteria: {self.detector}",
            "description": self.description,
            "vulnerability_type": self.detector,
            "severity": severity_map.get(self.impact, "medium"),
            "confidence": confidence_map.get(self.confidence, 0.6),
            "status": "proposed",
            "node_refs": [],
            "evidence": [],
            "properties": {
                "source_tool": "soteria",
                "source_files": [self.file_path] if self.file_path else [],
                "affected_lines": self.lines,
                "soteria_impact": self.impact,
                "soteria_confidence": self.confidence,
            },
        }


# Map known Soteria detector names to (impact, confidence) defaults
_DETECTOR_DEFAULTS: dict[str, tuple[str, str]] = {
    "missing-signer": ("High", "High"),
    "missing-owner": ("High", "High"),
    "overflow": ("Medium", "Medium"),
    "integer-overflow": ("Medium", "Medium"),
    "integer-underflow": ("Medium", "Medium"),
    "cpi-issue": ("High", "High"),
    "arbitrary-cpi": ("High", "High"),
    "missing-key-check": ("High", "High"),
    "insecure-account-close": ("Medium", "Medium"),
    "loss-of-precision": ("Low", "Medium"),
    "type-cosplay": ("High", "High"),
    "sysvar-account-check": ("Medium", "Medium"),
}


class SoteriaRunner:
    """Runs Soteria and parses its output."""

    def __init__(self, timeout: int = 300):
        """Initialize Soteria runner.

        Args:
            timeout: Maximum seconds to wait for Soteria
        """
        self.timeout = timeout

    def _find_project_root(self, path: Path) -> Path:
        """Find the Anchor/Solana project root by looking for config files.

        Args:
            path: Starting path to search from

        Returns:
            Project root path (falls back to input path if not found)
        """
        if path.is_file():
            path = path.parent

        # Config files that indicate a Solana/Anchor project root
        config_files = ["Anchor.toml", "Cargo.toml"]

        # Walk up the directory tree
        current = path.resolve()
        for _ in range(10):  # Limit depth
            for config in config_files:
                if (current / config).exists():
                    return current
            parent = current.parent
            if parent == current:
                break
            current = parent

        # Fallback: use the original path
        return path if path.is_dir() else path.parent

    def is_available(self) -> tuple[bool, str]:
        """Check if Soteria is installed.

        Returns:
            Tuple of (available, version_or_error)
        """
        soteria_cmd = self._find_soteria()
        if not soteria_cmd:
            return False, "soteria not found in PATH or common locations"

        try:
            result = subprocess.run(
                [soteria_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or result.stderr.strip()
                return True, version
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "timeout checking soteria version"
        except Exception as e:
            return False, str(e)

    def _find_soteria(self) -> str | None:
        """Find soteria executable in PATH or common locations."""
        import shutil

        # Check PATH first
        if shutil.which("soteria"):
            return "soteria"

        # Check common install locations
        base_dir = Path(__file__).parent.parent.parent
        common_paths = [
            base_dir / ".venv" / "bin" / "soteria",
            base_dir / "venv" / "bin" / "soteria",
            Path.home() / ".local" / "bin" / "soteria",
            Path.home() / ".cargo" / "bin" / "soteria",
        ]

        for path in common_paths:
            if path.exists():
                return str(path)

        return None

    def run(self, project_path: Path) -> tuple[list[SoteriaFinding], dict]:
        """Run Soteria on a Solana/Anchor project.

        Args:
            project_path: Path to Solana/Anchor project

        Returns:
            Tuple of (findings, metadata)
        """
        metadata: dict[str, Any] = {
            "tool": "soteria",
            "version": None,
            "success": False,
            "error": None,
        }

        # Check availability
        available, version = self.is_available()
        if not available:
            metadata["error"] = f"Soteria not available: {version}"
            return [], metadata

        metadata["version"] = version

        # Find project root
        project_root = self._find_project_root(project_path)

        try:
            soteria_cmd = self._find_soteria() or "soteria"

            cmd = [soteria_cmd, "-analyzeAll", "."]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=project_root,
            )

            # Soteria outputs findings to stdout as text
            # Combine stdout and stderr for parsing
            output = result.stdout + "\n" + result.stderr

            if not output.strip():
                metadata["error"] = "Soteria produced no output"
                return [], metadata

            metadata["success"] = True

            # Parse text output
            findings = self._parse_output(output)

            return findings, metadata

        except subprocess.TimeoutExpired:
            metadata["error"] = f"Soteria timed out after {self.timeout}s"
            return [], metadata
        except Exception as e:
            metadata["error"] = f"Soteria error: {e}"
            return [], metadata

    def _parse_output(self, output: str) -> list[SoteriaFinding]:
        """Parse Soteria's text output format.

        Soteria output format:
            Vulnerability found: <type>
            File: <path>
            Line: <number>
            Description: <text>
            Impact: <High|Medium|Low>

        Args:
            output: Raw text output from Soteria

        Returns:
            List of parsed findings
        """
        findings = []
        lines = output.splitlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Look for vulnerability start markers
            vuln_match = re.match(r"Vulnerability found:\s*(.+)", line, re.IGNORECASE)
            if vuln_match:
                detector = vuln_match.group(1).strip()
                file_path = ""
                line_nums: list[int] = []
                description = ""
                impact = ""

                # Parse the following block lines
                j = i + 1
                while j < len(lines):
                    block_line = lines[j].strip()
                    if not block_line:
                        j += 1
                        # Empty line may end the block; peek ahead for another Vulnerability
                        if j < len(lines) and re.match(
                            r"Vulnerability found:", lines[j].strip(), re.IGNORECASE
                        ):
                            break
                        continue

                    file_match = re.match(r"File:\s*(.+)", block_line, re.IGNORECASE)
                    if file_match:
                        file_path = file_match.group(1).strip()
                        j += 1
                        continue

                    line_match = re.match(r"Line:\s*(\d+)", block_line, re.IGNORECASE)
                    if line_match:
                        line_nums.append(int(line_match.group(1)))
                        j += 1
                        continue

                    desc_match = re.match(r"Description:\s*(.+)", block_line, re.IGNORECASE)
                    if desc_match:
                        description = desc_match.group(1).strip()
                        j += 1
                        continue

                    impact_match = re.match(r"Impact:\s*(.+)", block_line, re.IGNORECASE)
                    if impact_match:
                        impact = impact_match.group(1).strip()
                        j += 1
                        break  # Impact is typically the last field in a block

                    # If we hit another "Vulnerability found:", stop
                    if re.match(r"Vulnerability found:", block_line, re.IGNORECASE):
                        break

                    j += 1

                # Determine impact and confidence from detector defaults if not parsed
                detector_key = detector.lower().replace(" ", "-").replace("_", "-")
                defaults = _DETECTOR_DEFAULTS.get(detector_key, ("Medium", "Medium"))

                if not impact:
                    impact = defaults[0]
                confidence = defaults[1]

                # Normalize impact
                impact_normalized = impact.capitalize()
                if impact_normalized not in ("High", "Medium", "Low"):
                    impact_normalized = "Medium"

                finding = SoteriaFinding(
                    detector=detector,
                    impact=impact_normalized,
                    confidence=confidence,
                    description=description or f"Soteria detected: {detector}",
                    file_path=file_path,
                    lines=line_nums,
                )
                findings.append(finding)

                i = j
                continue

            i += 1

        return findings
