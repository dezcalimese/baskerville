"""
Static analysis pipeline orchestrator.

Runs multiple static analyzers (Slither, Aderyn, Soteria, cargo-audit,
Move Prover, Sui Move Lint) and aggregates their findings into Hound's
hypothesis system. Supports EVM, Solana, and Sui/Aptos chains.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .slither_runner import SlitherRunner, SlitherFinding
from .aderyn_runner import AderynRunner, AderynFinding
from .soteria_runner import SoteriaRunner, SoteriaFinding
from .cargo_audit_runner import CargoAuditRunner, CargoAuditFinding
from .move_prover_runner import MoveProverRunner, MoveProverFinding
from .sui_move_lint_runner import SuiMoveLintRunner, SuiMoveLintFinding


@dataclass
class PipelineResult:
    """Result from running the static analysis pipeline."""

    tool_findings: dict[str, list] = field(default_factory=dict)
    hypotheses: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    # Backward-compatible properties for EVM tools
    @property
    def slither_findings(self) -> list[SlitherFinding]:
        return self.tool_findings.get("slither", [])

    @slither_findings.setter
    def slither_findings(self, value: list[SlitherFinding]) -> None:
        self.tool_findings["slither"] = value

    @property
    def aderyn_findings(self) -> list[AderynFinding]:
        return self.tool_findings.get("aderyn", [])

    @aderyn_findings.setter
    def aderyn_findings(self, value: list[AderynFinding]) -> None:
        self.tool_findings["aderyn"] = value

    @property
    def total_findings(self) -> int:
        return sum(len(findings) for findings in self.tool_findings.values())

    @property
    def unique_hypotheses(self) -> int:
        return len(self.hypotheses)

    def summary(self) -> str:
        """Generate a summary string."""
        lines = [
            f"Static Analysis Results:",
        ]

        for tool_name, findings in self.tool_findings.items():
            lines.append(f"  {tool_name}: {len(findings)} findings")

        lines.append(f"  Unique hypotheses: {len(self.hypotheses)}")

        # Count by severity
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for hyp in self.hypotheses:
            sev = hyp.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append(f"  By severity: {severity_counts}")

        return "\n".join(lines)


# Map chain IDs to their respective runner classes and config key names
_CHAIN_RUNNERS: dict[str, list[tuple[str, type, str]]] = {
    "evm": [
        ("slither", SlitherRunner, "slither_config"),
        ("aderyn", AderynRunner, "aderyn_config"),
    ],
    "solana": [
        ("soteria", SoteriaRunner, "soteria_config"),
        ("cargo-audit", CargoAuditRunner, "cargo_audit_config"),
    ],
    "sui": [
        ("move-prover", MoveProverRunner, "move_prover_config"),
        ("sui-move-lint", SuiMoveLintRunner, "sui_move_lint_config"),
    ],
    "aptos": [
        ("move-prover", MoveProverRunner, "move_prover_config"),
        ("sui-move-lint", SuiMoveLintRunner, "sui_move_lint_config"),
    ],
}


class StaticAnalysisPipeline:
    """Orchestrates static analysis tools and aggregates findings."""

    def __init__(
        self,
        slither_config: dict | None = None,
        aderyn_config: dict | None = None,
        soteria_config: dict | None = None,
        cargo_audit_config: dict | None = None,
        move_prover_config: dict | None = None,
        sui_move_lint_config: dict | None = None,
        deduplicate: bool = True,
        line_tolerance: int = 2,
        chain_id: str = "evm",
    ):
        """Initialize the pipeline.

        Args:
            slither_config: Config dict for SlitherRunner
            aderyn_config: Config dict for AderynRunner
            soteria_config: Config dict for SoteriaRunner
            cargo_audit_config: Config dict for CargoAuditRunner
            move_prover_config: Config dict for MoveProverRunner
            sui_move_lint_config: Config dict for SuiMoveLintRunner
            deduplicate: Whether to deduplicate findings across tools
            line_tolerance: Line number tolerance for deduplication
            chain_id: Target chain ("evm", "solana", "sui", "aptos")
        """
        self.deduplicate = deduplicate
        self.line_tolerance = line_tolerance
        self.chain_id = chain_id.lower()

        # Collect all config dicts by their config key name
        all_configs = {
            "slither_config": slither_config,
            "aderyn_config": aderyn_config,
            "soteria_config": soteria_config,
            "cargo_audit_config": cargo_audit_config,
            "move_prover_config": move_prover_config,
            "sui_move_lint_config": sui_move_lint_config,
        }

        # Instantiate runners for the selected chain
        runner_specs = _CHAIN_RUNNERS.get(self.chain_id, _CHAIN_RUNNERS["evm"])
        self.runners: dict[str, Any] = {}
        for tool_name, runner_class, config_key in runner_specs:
            config = all_configs.get(config_key) or {}
            self.runners[tool_name] = runner_class(**config)

        # Keep backward-compatible attributes for EVM tools
        if self.chain_id == "evm":
            self.slither = self.runners.get("slither")
            self.aderyn = self.runners.get("aderyn")

    def check_tools(self) -> dict[str, tuple[bool, str]]:
        """Check which tools are available for the configured chain.

        Returns:
            Dict mapping tool name to (available, version_or_error)
        """
        return {
            name: runner.is_available()
            for name, runner in self.runners.items()
        }

    def run(self, project_path: Path) -> PipelineResult:
        """Run the full static analysis pipeline.

        Args:
            project_path: Path to project

        Returns:
            PipelineResult with findings and hypotheses
        """
        result = PipelineResult()
        result.metadata = {
            "project_path": str(project_path),
            "run_time": datetime.now().isoformat(),
            "chain_id": self.chain_id,
            "tools": {},
        }

        # Run each tool for the configured chain
        for tool_name, runner in self.runners.items():
            available, version_or_error = runner.is_available()
            if available:
                findings, metadata = runner.run(project_path)
                result.tool_findings[tool_name] = findings
                result.metadata["tools"][tool_name] = metadata
            else:
                result.metadata["tools"][tool_name] = {
                    "available": False,
                    "error": version_or_error,
                }

        # Convert all findings to hypotheses
        all_hypotheses = []

        for tool_name, findings in result.tool_findings.items():
            for finding in findings:
                hyp = finding.to_hypothesis()
                hyp["id"] = self._generate_hypothesis_id(hyp, tool_name)
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

        # Save raw findings per tool
        for tool_name, findings in result.tool_findings.items():
            if findings:
                tool_path = output_dir / f"{tool_name.replace('-', '_')}_findings.json"
                with open(tool_path, "w") as f:
                    json.dump(
                        [finding.to_hypothesis() for finding in findings],
                        f, indent=2,
                    )
                paths[tool_name] = tool_path

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
