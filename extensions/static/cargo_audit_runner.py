"""
Cargo audit wrapper for Rust/Solana dependency vulnerability scanning.

Runs `cargo audit --json` and parses JSON output into Hound hypothesis format.
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CargoAuditFinding:
    """A single finding from cargo-audit."""

    advisory_id: str
    title: str
    description: str
    severity: str  # High, Medium, Low, Info
    package: str
    version: str
    url: str = ""

    def to_hypothesis(self) -> dict[str, Any]:
        """Convert to Hound hypothesis format."""
        # Map CVSS-style severity to Hound severity
        severity_map = {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "none": "info",
        }

        # Map severity to confidence (known advisories are high confidence)
        confidence_map = {
            "critical": 0.95,
            "high": 0.95,
            "medium": 0.9,
            "low": 0.85,
            "informational": 0.8,
            "none": 0.7,
        }

        severity_lower = self.severity.lower()

        full_description = self.description
        if self.url:
            full_description += f"\n\nAdvisory: {self.url}"
        full_description += f"\nAffected package: {self.package} v{self.version}"

        return {
            "title": f"{self.advisory_id}: {self.title}",
            "description": full_description,
            "vulnerability_type": f"dependency-advisory-{self.advisory_id}",
            "severity": severity_map.get(severity_lower, "medium"),
            "confidence": confidence_map.get(severity_lower, 0.85),
            "status": "proposed",
            "node_refs": [],
            "evidence": [],
            "properties": {
                "source_tool": "cargo-audit",
                "source_files": [],
                "affected_lines": [],
                "advisory_id": self.advisory_id,
                "package": self.package,
                "version": self.version,
                "advisory_url": self.url,
                "cargo_audit_severity": self.severity,
            },
        }


class CargoAuditRunner:
    """Runs cargo-audit and parses its output."""

    def __init__(self, timeout: int = 120):
        """Initialize cargo-audit runner.

        Args:
            timeout: Maximum seconds to wait for cargo-audit
        """
        self.timeout = timeout

    def is_available(self) -> tuple[bool, str]:
        """Check if cargo-audit is installed.

        Returns:
            Tuple of (available, version_or_error)
        """
        import shutil

        if not shutil.which("cargo-audit"):
            # Also check as cargo subcommand
            try:
                result = subprocess.run(
                    ["cargo", "audit", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    version = result.stdout.strip() or result.stderr.strip()
                    return True, version
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            return False, "cargo-audit not found in PATH"

        try:
            result = subprocess.run(
                ["cargo-audit", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or result.stderr.strip()
                return True, version
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "timeout checking cargo-audit version"
        except Exception as e:
            return False, str(e)

    def _find_project_root(self, path: Path) -> Path:
        """Find Cargo project root by looking for Cargo.toml or Anchor.toml.

        Args:
            path: Starting path to search from

        Returns:
            Project root path (falls back to input path if not found)
        """
        if path.is_file():
            path = path.parent

        config_files = ["Cargo.toml", "Anchor.toml"]

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

    def run(self, project_path: Path) -> tuple[list[CargoAuditFinding], dict]:
        """Run cargo-audit on a project.

        Args:
            project_path: Path to Rust/Solana project

        Returns:
            Tuple of (findings, metadata)
        """
        metadata: dict[str, Any] = {
            "tool": "cargo-audit",
            "version": None,
            "success": False,
            "error": None,
        }

        # Check availability
        available, version = self.is_available()
        if not available:
            metadata["error"] = f"cargo-audit not available: {version}"
            return [], metadata

        metadata["version"] = version

        project_root = self._find_project_root(project_path)

        try:
            cmd = ["cargo", "audit", "--json"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=project_root,
            )

            # cargo-audit returns non-zero when vulnerabilities are found
            output = result.stdout.strip()
            if not output:
                # If no stdout, check stderr for errors
                if result.returncode != 0 and result.stderr:
                    metadata["error"] = f"cargo-audit failed: {result.stderr[:200]}"
                    return [], metadata
                # No output and success means no advisories
                metadata["success"] = True
                return [], metadata

            # Parse JSON output
            try:
                raw_data = json.loads(output)
            except json.JSONDecodeError as e:
                metadata["error"] = f"JSON parse error: {e}. Output: {output[:200]}"
                return [], metadata

            metadata["success"] = True

            # Parse findings
            findings = self._parse_findings(raw_data)

            return findings, metadata

        except subprocess.TimeoutExpired:
            metadata["error"] = f"cargo-audit timed out after {self.timeout}s"
            return [], metadata
        except Exception as e:
            metadata["error"] = f"cargo-audit error: {e}"
            return [], metadata

    def _parse_findings(self, raw_data: dict) -> list[CargoAuditFinding]:
        """Parse cargo-audit JSON output into findings.

        The JSON format from cargo-audit includes a `vulnerabilities` object
        with a `list` array of advisory entries.
        """
        findings = []

        vulnerabilities = raw_data.get("vulnerabilities", {})
        advisory_list = vulnerabilities.get("list", [])

        for entry in advisory_list:
            advisory = entry.get("advisory", {})
            package_info = entry.get("package", {})
            versions = entry.get("versions", {})

            advisory_id = advisory.get("id", "UNKNOWN")
            title = advisory.get("title", "")
            description = advisory.get("description", "")
            url = advisory.get("url", "")

            package_name = package_info.get("name", "unknown")
            package_version = package_info.get("version", "unknown")

            # Determine severity from CVSS or advisory metadata
            severity = self._determine_severity(advisory, versions)

            finding = CargoAuditFinding(
                advisory_id=advisory_id,
                title=title,
                description=description,
                severity=severity,
                package=package_name,
                version=package_version,
                url=url,
            )
            findings.append(finding)

        return findings

    def _determine_severity(self, advisory: dict, versions: dict) -> str:
        """Determine severity from advisory CVSS score or keywords.

        Args:
            advisory: Advisory dict from cargo-audit output
            versions: Versions info from cargo-audit output

        Returns:
            Severity string: Critical, High, Medium, Low, or Informational
        """
        # Check for explicit CVSS score
        cvss = advisory.get("cvss", None)
        if cvss:
            # CVSS v3 score mapping
            score = None
            if isinstance(cvss, (int, float)):
                score = float(cvss)
            elif isinstance(cvss, str):
                # Sometimes the CVSS is a vector string; try to extract base score
                try:
                    score = float(cvss)
                except ValueError:
                    pass

            if score is not None:
                if score >= 9.0:
                    return "Critical"
                elif score >= 7.0:
                    return "High"
                elif score >= 4.0:
                    return "Medium"
                elif score > 0.0:
                    return "Low"
                else:
                    return "Informational"

        # Check keywords in advisory for severity hints
        keywords = advisory.get("keywords", [])
        title = advisory.get("title", "").lower()
        description = advisory.get("description", "").lower()

        high_indicators = ["remote code execution", "rce", "arbitrary code", "memory corruption"]
        medium_indicators = ["denial of service", "dos", "overflow", "underflow", "panic"]

        combined_text = f"{title} {description}"
        for indicator in high_indicators:
            if indicator in combined_text:
                return "High"
        for indicator in medium_indicators:
            if indicator in combined_text:
                return "Medium"

        # Default to Medium for known vulnerabilities
        return "Medium"
