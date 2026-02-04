"""
Slither static analyzer wrapper.

Runs Slither (Trail of Bits) and parses JSON output into Hound hypothesis format.
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SlitherFinding:
    """A single finding from Slither."""

    detector: str
    impact: str  # High, Medium, Low, Informational
    confidence: str  # High, Medium, Low
    description: str
    elements: list[dict] = field(default_factory=list)

    @property
    def file_path(self) -> str | None:
        """Get the primary file path from elements."""
        if self.elements:
            mapping = self.elements[0].get("source_mapping", {})
            return mapping.get("filename_relative")
        return None

    @property
    def lines(self) -> list[int]:
        """Get affected line numbers."""
        if self.elements:
            mapping = self.elements[0].get("source_mapping", {})
            return mapping.get("lines", [])
        return []

    @property
    def element_name(self) -> str:
        """Get the name of the first affected element."""
        if self.elements:
            return self.elements[0].get("name", "Unknown")
        return "Unknown"

    def to_hypothesis(self) -> dict[str, Any]:
        """Convert to Hound hypothesis format."""
        # Map Slither impact to Hound severity
        severity_map = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info",
            "Optimization": "info",
        }

        # Map Slither confidence to numeric value
        confidence_map = {
            "High": 0.9,
            "Medium": 0.7,
            "Low": 0.5,
        }

        # Build affected code info
        affected_code = ""
        if self.file_path:
            affected_code = f"{self.file_path}"
            if self.lines:
                affected_code += f":{self.lines[0]}-{self.lines[-1]}"

        return {
            "title": f"{self.detector}: {self.element_name}",
            "description": self.description,
            "vulnerability_type": self.detector,
            "severity": severity_map.get(self.impact, "medium"),
            "confidence": confidence_map.get(self.confidence, 0.6),
            "status": "proposed",
            "node_refs": [],
            "evidence": [],
            "properties": {
                "source_tool": "slither",
                "source_files": [self.file_path] if self.file_path else [],
                "affected_lines": self.lines,
                "slither_impact": self.impact,
                "slither_confidence": self.confidence,
            },
        }


class SlitherRunner:
    """Runs Slither and parses its output."""

    # Detectors to exclude by default (too noisy or low-value)
    DEFAULT_EXCLUDE = [
        "solc-version",
        "pragma",
        "naming-convention",
        "too-many-digits",
        "similar-names",
    ]

    def __init__(
        self,
        timeout: int = 300,
        exclude_detectors: list[str] | None = None,
        min_impact: str = "Low",  # High, Medium, Low, Informational
        min_confidence: str = "Low",  # High, Medium, Low
    ):
        """Initialize Slither runner.

        Args:
            timeout: Maximum seconds to wait for Slither
            exclude_detectors: List of detector names to skip
            min_impact: Minimum impact level to include
            min_confidence: Minimum confidence level to include
        """
        self.timeout = timeout
        self.exclude_detectors = exclude_detectors or self.DEFAULT_EXCLUDE
        self.min_impact = min_impact
        self.min_confidence = min_confidence

        # Impact and confidence ordering
        self._impact_order = ["High", "Medium", "Low", "Informational", "Optimization"]
        self._confidence_order = ["High", "Medium", "Low"]

        # Cached slither command path
        self._slither_cmd: str | None = None

    def _find_project_root(self, path: Path) -> Path:
        """Find the Foundry/Hardhat project root by looking for config files.

        Args:
            path: Starting path to search from

        Returns:
            Project root path (falls back to input path if not found)
        """
        if path.is_file():
            path = path.parent

        # Config files that indicate project root
        config_files = ["foundry.toml", "hardhat.config.js", "hardhat.config.ts"]

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
        """Check if Slither is installed.

        Returns:
            Tuple of (available, version_or_error)
        """
        slither_cmd = self._find_slither()
        if not slither_cmd:
            return False, "slither not found in PATH or venv"

        try:
            result = subprocess.run(
                [slither_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or result.stderr.strip()
                self._slither_cmd = slither_cmd  # Cache for run()
                return True, version
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "timeout checking slither version"
        except Exception as e:
            return False, str(e)

    def _find_slither(self) -> str | None:
        """Find slither executable in PATH or venv."""
        import shutil

        # Check PATH first
        if shutil.which("slither"):
            return "slither"

        # Check common venv locations relative to this file
        base_dir = Path(__file__).parent.parent.parent
        venv_paths = [
            base_dir / ".venv" / "bin" / "slither",
            base_dir / "venv" / "bin" / "slither",
            Path.home() / ".local" / "bin" / "slither",
        ]

        for path in venv_paths:
            if path.exists():
                return str(path)

        return None

    def run(self, project_path: Path) -> tuple[list[SlitherFinding], dict]:
        """Run Slither on a project.

        Args:
            project_path: Path to Solidity project or file

        Returns:
            Tuple of (findings, metadata)
        """
        metadata = {
            "tool": "slither",
            "version": None,
            "success": False,
            "error": None,
            "raw_output_path": None,
        }

        # Check availability
        available, version = self.is_available()
        if not available:
            metadata["error"] = f"Slither not available: {version}"
            return [], metadata

        metadata["version"] = version

        # Run Slither with JSON output
        # Generate a unique temp path (don't create the file - Slither won't overwrite)
        import os as _os
        import uuid
        output_path = Path(tempfile.gettempdir()) / f"slither_{uuid.uuid4().hex}.json"

        try:
            slither_cmd = getattr(self, "_slither_cmd", None) or self._find_slither() or "slither"

            # Run from project root (where foundry.toml/hardhat.config exists)
            project_root = self._find_project_root(project_path)

            # Make project_path relative to project_root for slither
            try:
                rel_path = project_path.resolve().relative_to(project_root)
            except ValueError:
                rel_path = project_path.resolve()

            cmd = [
                slither_cmd,
                str(rel_path),
                "--json", str(output_path.resolve()),  # Ensure absolute path for output
            ]

            # Add exclude filters
            for detector in self.exclude_detectors:
                cmd.extend(["--exclude", detector])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=project_root,
            )

            # Slither returns non-zero even on success if findings exist
            # Check if JSON was written
            if not output_path.exists() or output_path.stat().st_size == 0:
                # Try stderr for error message
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                metadata["error"] = f"Slither failed (no output): {error_msg[:200]}"
                return [], metadata

            # Parse JSON output
            try:
                with open(output_path) as f:
                    raw_data = json.load(f)
            except json.JSONDecodeError as e:
                # Read raw content for debugging
                content = output_path.read_text()[:500]
                metadata["error"] = f"JSON parse error: {e}. Content: {content}"
                return [], metadata

            metadata["raw_output_path"] = str(output_path)

            if not raw_data.get("success", False):
                metadata["error"] = raw_data.get("error", "Unknown Slither error")
                return [], metadata

            metadata["success"] = True

            # Parse findings
            findings = self._parse_findings(raw_data)

            return findings, metadata

        except subprocess.TimeoutExpired:
            metadata["error"] = f"Slither timed out after {self.timeout}s"
            return [], metadata
        except json.JSONDecodeError as e:
            metadata["error"] = f"Failed to parse Slither JSON: {e}"
            return [], metadata
        except Exception as e:
            metadata["error"] = f"Slither error: {e}"
            return [], metadata

    def _parse_findings(self, raw_data: dict) -> list[SlitherFinding]:
        """Parse Slither JSON output into findings."""
        findings = []

        detectors = raw_data.get("results", {}).get("detectors", [])

        for detector in detectors:
            # Filter by detector name
            check = detector.get("check", "")
            if check in self.exclude_detectors:
                continue

            # Filter by impact
            impact = detector.get("impact", "Informational")
            if not self._meets_threshold(impact, self.min_impact, self._impact_order):
                continue

            # Filter by confidence
            confidence = detector.get("confidence", "Low")
            if not self._meets_threshold(confidence, self.min_confidence, self._confidence_order):
                continue

            finding = SlitherFinding(
                detector=check,
                impact=impact,
                confidence=confidence,
                description=detector.get("description", ""),
                elements=detector.get("elements", []),
            )
            findings.append(finding)

        return findings

    def _meets_threshold(self, value: str, threshold: str, order: list[str]) -> bool:
        """Check if a value meets the minimum threshold."""
        try:
            value_idx = order.index(value)
            threshold_idx = order.index(threshold)
            return value_idx <= threshold_idx
        except ValueError:
            return True  # Unknown values pass through
