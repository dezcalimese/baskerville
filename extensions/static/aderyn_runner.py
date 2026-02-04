"""
Aderyn static analyzer wrapper.

Runs Aderyn (Cyfrin) and parses JSON output into Hound hypothesis format.
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AderynInstance:
    """A single instance of a finding."""

    contract_path: str
    line_no: int
    src: str = ""
    node_id: str | None = None


@dataclass
class AderynFinding:
    """A single finding from Aderyn."""

    title: str
    description: str
    detector_name: str
    severity: str  # High, Medium, Low, NC
    instances: list[AderynInstance] = field(default_factory=list)

    def to_hypothesis(self) -> dict[str, Any]:
        """Convert to Hound hypothesis format."""
        # Map Aderyn severity to Hound severity
        severity_map = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "NC": "info",
        }

        # Aderyn doesn't provide confidence, estimate from severity
        confidence_map = {
            "High": 0.85,
            "Medium": 0.7,
            "Low": 0.6,
            "NC": 0.5,
        }

        # Build affected code info
        source_files = list(set(inst.contract_path for inst in self.instances))
        affected_lines = [inst.line_no for inst in self.instances]

        # Build description with instances
        full_description = self.description
        if self.instances:
            full_description += "\n\nAffected locations:\n"
            for inst in self.instances[:5]:  # Limit to first 5
                full_description += f"- {inst.contract_path}:{inst.line_no}"
                if inst.src:
                    # Truncate long snippets
                    snippet = inst.src[:100] + "..." if len(inst.src) > 100 else inst.src
                    full_description += f": {snippet}"
                full_description += "\n"
            if len(self.instances) > 5:
                full_description += f"- ... and {len(self.instances) - 5} more\n"

        return {
            "title": self.title,
            "description": full_description,
            "vulnerability_type": self.detector_name,
            "severity": severity_map.get(self.severity, "medium"),
            "confidence": confidence_map.get(self.severity, 0.6),
            "status": "proposed",
            "node_refs": [],
            "evidence": [],
            "properties": {
                "source_tool": "aderyn",
                "source_files": source_files,
                "affected_lines": affected_lines,
                "aderyn_severity": self.severity,
                "instance_count": len(self.instances),
            },
        }


class AderynRunner:
    """Runs Aderyn and parses its output."""

    # Detectors to exclude by default
    DEFAULT_EXCLUDE: list[str] = []

    def __init__(
        self,
        timeout: int = 120,
        exclude_detectors: list[str] | None = None,
        min_severity: str = "Low",  # High, Medium, Low, NC
    ):
        """Initialize Aderyn runner.

        Args:
            timeout: Maximum seconds to wait for Aderyn
            exclude_detectors: List of detector names to skip
            min_severity: Minimum severity level to include
        """
        self.timeout = timeout
        self.exclude_detectors = exclude_detectors or self.DEFAULT_EXCLUDE
        self.min_severity = min_severity

        # Severity ordering
        self._severity_order = ["High", "Medium", "Low", "NC"]

    def _find_project_root(self, path: Path) -> Path | None:
        """Find the Foundry/Hardhat project root by looking for config files.

        Args:
            path: Starting path to search from

        Returns:
            Project root path or None if not found
        """
        if path.is_file():
            path = path.parent

        # Config files that indicate project root
        config_files = ["foundry.toml", "hardhat.config.js", "hardhat.config.ts"]

        # Walk up the directory tree
        current = path.resolve()
        for _ in range(10):  # Limit depth to avoid infinite loop
            for config in config_files:
                if (current / config).exists():
                    return current
            parent = current.parent
            if parent == current:
                break  # Reached filesystem root
            current = parent

        # Fallback: use the original path if it's a directory
        return path if path.is_dir() else path.parent

    def is_available(self) -> tuple[bool, str]:
        """Check if Aderyn is installed.

        Returns:
            Tuple of (available, version_or_error)
        """
        try:
            result = subprocess.run(
                ["aderyn", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or result.stderr.strip()
                return True, version
            return False, result.stderr.strip()
        except FileNotFoundError:
            return False, "aderyn not found in PATH"
        except subprocess.TimeoutExpired:
            return False, "timeout checking aderyn version"
        except Exception as e:
            return False, str(e)

    def run(self, project_path: Path) -> tuple[list[AderynFinding], dict]:
        """Run Aderyn on a project.

        Args:
            project_path: Path to Solidity project

        Returns:
            Tuple of (findings, metadata)
        """
        metadata = {
            "tool": "aderyn",
            "version": None,
            "success": False,
            "error": None,
            "raw_output_path": None,
            "files_analyzed": 0,
            "total_sloc": 0,
        }

        # Check availability
        available, version = self.is_available()
        if not available:
            metadata["error"] = f"Aderyn not available: {version}"
            return [], metadata

        metadata["version"] = version

        # Aderyn expects to run from Foundry/Hardhat project root
        project_dir = self._find_project_root(project_path)
        if not project_dir:
            metadata["error"] = "Could not find Foundry/Hardhat project root (no foundry.toml or hardhat.config found)"
            return [], metadata

        # Run Aderyn with JSON output
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            output_path = Path(tmp.name)

        try:
            cmd = [
                "aderyn",
                str(project_dir),
                "-o", str(output_path),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=project_dir,
            )

            # Check if JSON was written
            if not output_path.exists() or output_path.stat().st_size == 0:
                metadata["error"] = f"Aderyn failed: {result.stderr or result.stdout}"
                return [], metadata

            # Parse JSON output
            with open(output_path) as f:
                raw_data = json.load(f)

            metadata["raw_output_path"] = str(output_path)
            metadata["success"] = True

            # Extract summary info if available
            files_summary = raw_data.get("files_summary", {})
            metadata["files_analyzed"] = files_summary.get("total_source_units", 0)
            metadata["total_sloc"] = files_summary.get("total_sloc", 0)

            # Parse findings
            findings = self._parse_findings(raw_data)

            return findings, metadata

        except subprocess.TimeoutExpired:
            metadata["error"] = f"Aderyn timed out after {self.timeout}s"
            return [], metadata
        except json.JSONDecodeError as e:
            metadata["error"] = f"Failed to parse Aderyn JSON: {e}"
            return [], metadata
        except Exception as e:
            metadata["error"] = f"Aderyn error: {e}"
            return [], metadata

    def _parse_findings(self, raw_data: dict) -> list[AderynFinding]:
        """Parse Aderyn JSON output into findings."""
        findings = []

        # Aderyn uses different keys for different output versions
        # Try "issues" first, then "high_issues", "medium_issues", etc.
        issues = raw_data.get("issues", [])

        # If no "issues" key, try to gather from severity-specific keys
        if not issues:
            for severity in ["high_issues", "medium_issues", "low_issues", "nc_issues"]:
                issues.extend(raw_data.get(severity, []))

        for issue in issues:
            # Filter by detector name
            detector_name = issue.get("detector_name", "")
            if detector_name in self.exclude_detectors:
                continue

            # Determine severity
            severity = issue.get("severity", "Medium")
            # Normalize severity names
            if severity.lower() in ["high", "critical"]:
                severity = "High"
            elif severity.lower() == "medium":
                severity = "Medium"
            elif severity.lower() == "low":
                severity = "Low"
            else:
                severity = "NC"

            # Filter by severity
            if not self._meets_threshold(severity, self.min_severity):
                continue

            # Parse instances
            instances = []
            for inst in issue.get("instances", []):
                instances.append(
                    AderynInstance(
                        contract_path=inst.get("contract_path", ""),
                        line_no=inst.get("line_no", 0),
                        src=inst.get("src", ""),
                        node_id=inst.get("node_id"),
                    )
                )

            finding = AderynFinding(
                title=issue.get("title", detector_name),
                description=issue.get("description", ""),
                detector_name=detector_name,
                severity=severity,
                instances=instances,
            )
            findings.append(finding)

        return findings

    def _meets_threshold(self, value: str, threshold: str) -> bool:
        """Check if a severity meets the minimum threshold."""
        try:
            value_idx = self._severity_order.index(value)
            threshold_idx = self._severity_order.index(threshold)
            return value_idx <= threshold_idx
        except ValueError:
            return True  # Unknown values pass through
