"""
Static analysis pipeline orchestrator.

Runs multiple static analyzers (Slither, Aderyn) and aggregates
their findings into Hound's hypothesis system.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .slither_runner import SlitherRunner, SlitherFinding
from .aderyn_runner import AderynRunner, AderynFinding


@dataclass
class PipelineResult:
    """Result from running the static analysis pipeline."""

    slither_findings: list[SlitherFinding] = field(default_factory=list)
    aderyn_findings: list[AderynFinding] = field(default_factory=list)
    hypotheses: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.slither_findings) + len(self.aderyn_findings)

    @property
    def unique_hypotheses(self) -> int:
        return len(self.hypotheses)

    def summary(self) -> str:
        """Generate a summary string."""
        lines = [
            f"Static Analysis Results:",
            f"  Slither: {len(self.slither_findings)} findings",
            f"  Aderyn: {len(self.aderyn_findings)} findings",
            f"  Unique hypotheses: {len(self.hypotheses)}",
        ]

        # Count by severity
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for hyp in self.hypotheses:
            sev = hyp.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append(f"  By severity: {severity_counts}")

        return "\n".join(lines)


class StaticAnalysisPipeline:
    """Orchestrates static analysis tools and aggregates findings."""

    def __init__(
        self,
        slither_config: dict | None = None,
        aderyn_config: dict | None = None,
        deduplicate: bool = True,
        line_tolerance: int = 2,
    ):
        """Initialize the pipeline.

        Args:
            slither_config: Config dict for SlitherRunner
            aderyn_config: Config dict for AderynRunner
            deduplicate: Whether to deduplicate findings across tools
            line_tolerance: Line number tolerance for deduplication
        """
        self.slither = SlitherRunner(**(slither_config or {}))
        self.aderyn = AderynRunner(**(aderyn_config or {}))
        self.deduplicate = deduplicate
        self.line_tolerance = line_tolerance

    def check_tools(self) -> dict[str, tuple[bool, str]]:
        """Check which tools are available.

        Returns:
            Dict mapping tool name to (available, version_or_error)
        """
        return {
            "slither": self.slither.is_available(),
            "aderyn": self.aderyn.is_available(),
        }

    def run(self, project_path: Path) -> PipelineResult:
        """Run the full static analysis pipeline.

        Args:
            project_path: Path to Solidity project

        Returns:
            PipelineResult with findings and hypotheses
        """
        result = PipelineResult()
        result.metadata = {
            "project_path": str(project_path),
            "run_time": datetime.now().isoformat(),
            "tools": {},
        }

        # Run Slither
        slither_available, slither_version = self.slither.is_available()
        if slither_available:
            findings, metadata = self.slither.run(project_path)
            result.slither_findings = findings
            result.metadata["tools"]["slither"] = metadata
        else:
            result.metadata["tools"]["slither"] = {
                "available": False,
                "error": slither_version,
            }

        # Run Aderyn
        aderyn_available, aderyn_version = self.aderyn.is_available()
        if aderyn_available:
            findings, metadata = self.aderyn.run(project_path)
            result.aderyn_findings = findings
            result.metadata["tools"]["aderyn"] = metadata
        else:
            result.metadata["tools"]["aderyn"] = {
                "available": False,
                "error": aderyn_version,
            }

        # Convert to hypotheses
        all_hypotheses = []

        for finding in result.slither_findings:
            hyp = finding.to_hypothesis()
            hyp["id"] = self._generate_hypothesis_id(hyp, "slither")
            all_hypotheses.append(hyp)

        for finding in result.aderyn_findings:
            hyp = finding.to_hypothesis()
            hyp["id"] = self._generate_hypothesis_id(hyp, "aderyn")
            all_hypotheses.append(hyp)

        # Deduplicate if enabled
        if self.deduplicate:
            result.hypotheses = self._deduplicate_hypotheses(all_hypotheses)
        else:
            result.hypotheses = all_hypotheses

        return result

    def _generate_hypothesis_id(self, hypothesis: dict, tool: str) -> str:
        """Generate a unique ID for a hypothesis."""
        # Use hash of key fields for dedup-friendly IDs
        key_parts = [
            tool,
            hypothesis.get("vulnerability_type", ""),
            hypothesis.get("title", ""),
            str(hypothesis.get("properties", {}).get("source_files", [])),
        ]
        key_string = "|".join(key_parts)
        hash_suffix = hashlib.md5(key_string.encode()).hexdigest()[:8]
        return f"static_{tool}_{hash_suffix}"

    def _deduplicate_hypotheses(self, hypotheses: list[dict]) -> list[dict]:
        """Remove duplicate findings across tools.

        Uses file path, line numbers, and vulnerability type for matching.
        """
        unique = []
        seen_keys = set()

        # Sort by confidence (higher first) so we keep the best version
        sorted_hyps = sorted(
            hypotheses,
            key=lambda h: h.get("confidence", 0),
            reverse=True,
        )

        for hyp in sorted_hyps:
            key = self._make_dedup_key(hyp)
            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(hyp)

        return unique

    def _make_dedup_key(self, hypothesis: dict) -> str:
        """Create a deduplication key for a hypothesis."""
        props = hypothesis.get("properties", {})
        files = props.get("source_files", [])
        lines = props.get("affected_lines", [])
        vuln_type = hypothesis.get("vulnerability_type", "")

        # Normalize vulnerability types across tools
        vuln_type_normalized = self._normalize_vuln_type(vuln_type)

        # Use first file and line range (with tolerance)
        file_key = files[0] if files else ""
        line_key = ""
        if lines:
            # Round to tolerance bucket
            min_line = min(lines) // self.line_tolerance * self.line_tolerance
            line_key = str(min_line)

        return f"{file_key}|{line_key}|{vuln_type_normalized}"

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type names across tools."""
        # Map common equivalent detectors
        equivalents = {
            # Reentrancy variants
            "reentrancy-eth": "reentrancy",
            "reentrancy-no-eth": "reentrancy",
            "reentrancy-benign": "reentrancy",
            "reentrancy-events": "reentrancy",
            "reentrancy-unlimited-gas": "reentrancy",
            # Uninitialized
            "uninitialized-state": "uninitialized",
            "uninitialized-local": "uninitialized",
            "uninitialized-storage": "uninitialized",
            # Unchecked
            "unchecked-transfer": "unchecked-return",
            "unchecked-lowlevel": "unchecked-return",
            "unchecked-send": "unchecked-return",
        }

        normalized = vuln_type.lower().replace("_", "-")
        return equivalents.get(normalized, normalized)

    def save_results(self, result: PipelineResult, output_dir: Path) -> dict[str, Path]:
        """Save pipeline results to files.

        Args:
            result: The pipeline result to save
            output_dir: Directory to save files in

        Returns:
            Dict mapping file type to path
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        paths = {}

        # Save hypotheses
        hypotheses_path = output_dir / "static_hypotheses.json"
        with open(hypotheses_path, "w") as f:
            json.dump(result.hypotheses, f, indent=2)
        paths["hypotheses"] = hypotheses_path

        # Save metadata
        metadata_path = output_dir / "static_metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(result.metadata, f, indent=2)
        paths["metadata"] = metadata_path

        # Save raw findings
        if result.slither_findings:
            slither_path = output_dir / "slither_findings.json"
            with open(slither_path, "w") as f:
                json.dump(
                    [f.to_hypothesis() for f in result.slither_findings],
                    f, indent=2
                )
            paths["slither"] = slither_path

        if result.aderyn_findings:
            aderyn_path = output_dir / "aderyn_findings.json"
            with open(aderyn_path, "w") as f:
                json.dump(
                    [f.to_hypothesis() for f in result.aderyn_findings],
                    f, indent=2
                )
            paths["aderyn"] = aderyn_path

        return paths

    def import_to_hypothesis_store(
        self,
        result: PipelineResult,
        hypothesis_store_path: Path,
    ) -> int:
        """Import static analysis findings into Hound's hypothesis store.

        Args:
            result: Pipeline result with hypotheses
            hypothesis_store_path: Path to hypotheses.json

        Returns:
            Number of hypotheses imported
        """
        # Load existing hypotheses
        if hypothesis_store_path.exists():
            with open(hypothesis_store_path) as f:
                store = json.load(f)
        else:
            store = {"version": "1.0", "hypotheses": {}}

        # Add new hypotheses (skip duplicates by ID)
        imported = 0
        for hyp in result.hypotheses:
            hyp_id = hyp.get("id", "")
            if hyp_id and hyp_id not in store["hypotheses"]:
                # Add timestamp
                hyp["created_at"] = datetime.now().isoformat()
                hyp["created_by"] = "static_analysis"
                store["hypotheses"][hyp_id] = hyp
                imported += 1

        # Save updated store
        with open(hypothesis_store_path, "w") as f:
            json.dump(store, f, indent=2)

        return imported
