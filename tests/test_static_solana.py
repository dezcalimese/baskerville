"""
Tests for Solana static analysis runners.

Tests SoteriaRunner and CargoAuditRunner with mocked subprocess output.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from extensions.static.soteria_runner import SoteriaRunner, SoteriaFinding
from extensions.static.cargo_audit_runner import CargoAuditRunner, CargoAuditFinding
from extensions.static.pipeline import StaticAnalysisPipeline, PipelineResult


class TestSoteriaFinding:
    """Test SoteriaFinding dataclass and hypothesis conversion."""

    def test_to_hypothesis_high_severity(self):
        finding = SoteriaFinding(
            detector="missing-signer",
            impact="High",
            confidence="High",
            description="Missing signer check in withdraw instruction",
            file_path="programs/vault/src/lib.rs",
            lines=[42],
        )
        hyp = finding.to_hypothesis()

        assert hyp["title"] == "Soteria: missing-signer"
        assert hyp["severity"] == "high"
        assert hyp["confidence"] == 0.9
        assert "missing signer" in hyp["description"].lower()
        assert hyp["properties"]["source_tool"] == "soteria"
        assert "programs/vault/src/lib.rs" in hyp["properties"]["source_files"]

    def test_to_hypothesis_medium_severity(self):
        finding = SoteriaFinding(
            detector="overflow",
            impact="Medium",
            confidence="Medium",
            description="Potential integer overflow in calculation",
        )
        hyp = finding.to_hypothesis()

        assert hyp["severity"] == "medium"
        assert hyp["confidence"] == 0.7

    def test_to_hypothesis_minimal(self):
        finding = SoteriaFinding(
            detector="test",
            impact="Low",
            confidence="Low",
            description="Test finding",
        )
        hyp = finding.to_hypothesis()

        assert hyp["severity"] == "low"
        assert "status" in hyp


class TestSoteriaRunner:
    """Test SoteriaRunner with mocked subprocess."""

    def test_is_available_when_installed(self):
        with patch("shutil.which", return_value="/usr/bin/soteria"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="Soteria v0.3.0",
                    stderr="",
                )
                runner = SoteriaRunner()
                available, version = runner.is_available()
                assert available is True
                assert "0.3.0" in version

    def test_is_available_when_not_installed(self):
        with patch("shutil.which", return_value=None):
            runner = SoteriaRunner()
            available, msg = runner.is_available()
            assert available is False

    def test_run_parses_findings(self):
        """Test parsing typical Soteria output."""
        sample_output = """
Soteria analysis started...
Analyzing program: vault

Vulnerability found: missing-signer
  File: programs/vault/src/lib.rs
  Line: 42
  Description: Missing signer check on authority account
  Impact: High
  Confidence: High

Vulnerability found: overflow
  File: programs/vault/src/lib.rs
  Line: 87
  Description: Potential integer overflow in deposit calculation
  Impact: Medium
  Confidence: Medium

Analysis complete. 2 vulnerabilities found.
"""
        with patch.object(SoteriaRunner, "is_available", return_value=(True, "0.3.0")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=sample_output,
                    stderr="",
                )
                runner = SoteriaRunner()
                findings, metadata = runner.run(Path("/tmp/test-project"))

                assert metadata["success"] is True
                assert len(findings) >= 1


class TestCargoAuditFinding:
    """Test CargoAuditFinding dataclass and hypothesis conversion."""

    def test_to_hypothesis(self):
        finding = CargoAuditFinding(
            advisory_id="RUSTSEC-2023-0001",
            title="Memory safety issue in borsh",
            description="A buffer overflow vulnerability in borsh deserialization",
            severity="High",
            package="borsh",
            version="0.9.0",
            url="https://rustsec.org/advisories/RUSTSEC-2023-0001",
        )
        hyp = finding.to_hypothesis()

        assert "RUSTSEC-2023-0001" in hyp["title"]
        assert hyp["severity"] == "high"
        assert hyp["properties"]["source_tool"] == "cargo-audit"
        assert hyp["properties"]["package"] == "borsh"

    def test_to_hypothesis_critical(self):
        finding = CargoAuditFinding(
            advisory_id="RUSTSEC-2024-0002",
            title="Critical RCE in dep",
            description="Remote code execution",
            severity="Critical",
            package="bad-dep",
            version="1.0.0",
            url="https://rustsec.org/advisories/RUSTSEC-2024-0002",
        )
        hyp = finding.to_hypothesis()
        # cargo-audit maps "critical" to "high" in Hound's severity model
        assert hyp["severity"] == "high"


class TestCargoAuditRunner:
    """Test CargoAuditRunner with mocked subprocess."""

    def test_is_available_when_installed(self):
        with patch("shutil.which", return_value="/usr/bin/cargo-audit"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="cargo-audit 0.18.0",
                    stderr="",
                )
                runner = CargoAuditRunner()
                available, version = runner.is_available()
                assert available is True

    def test_is_available_when_not_installed(self):
        with patch("shutil.which", return_value=None):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                runner = CargoAuditRunner()
                available, msg = runner.is_available()
                assert available is False

    def test_run_parses_json_output(self):
        """Test parsing cargo audit JSON output."""
        sample_json = {
            "vulnerabilities": {
                "found": True,
                "count": 1,
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2023-0001",
                            "title": "Test vulnerability",
                            "description": "A test vulnerability",
                            "url": "https://rustsec.org/advisories/RUSTSEC-2023-0001",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                        "package": {
                            "name": "test-crate",
                            "version": "1.0.0",
                        },
                        "versions": {"patched": [">=1.0.1"]},
                    }
                ],
            }
        }

        with patch.object(CargoAuditRunner, "is_available", return_value=(True, "0.18.0")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=json.dumps(sample_json),
                    stderr="",
                )
                runner = CargoAuditRunner()
                findings, metadata = runner.run(Path("/tmp/test-project"))

                assert metadata["success"] is True
                assert len(findings) >= 1
                if findings:
                    assert findings[0].advisory_id == "RUSTSEC-2023-0001"


class TestSolanaPipeline:
    """Test the static analysis pipeline with Solana chain."""

    def test_solana_pipeline_selects_correct_runners(self):
        pipeline = StaticAnalysisPipeline(chain_id="solana")
        assert "soteria" in pipeline.runners
        assert "cargo-audit" in pipeline.runners
        assert "slither" not in pipeline.runners
        assert "aderyn" not in pipeline.runners

    def test_evm_pipeline_selects_correct_runners(self):
        pipeline = StaticAnalysisPipeline(chain_id="evm")
        assert "slither" in pipeline.runners
        assert "aderyn" in pipeline.runners
        assert "soteria" not in pipeline.runners

    def test_pipeline_result_backward_compat(self):
        """PipelineResult backward-compatible properties still work."""
        result = PipelineResult()
        result.tool_findings["slither"] = [MagicMock()]
        assert len(result.slither_findings) == 1
        assert result.total_findings == 1

    def test_pipeline_result_multi_tool(self):
        result = PipelineResult()
        result.tool_findings["soteria"] = [MagicMock(), MagicMock()]
        result.tool_findings["cargo-audit"] = [MagicMock()]
        assert result.total_findings == 3

    def test_pipeline_summary(self):
        result = PipelineResult()
        result.tool_findings["soteria"] = [MagicMock()]
        result.hypotheses = [{"severity": "high"}]
        summary = result.summary()
        assert "soteria" in summary
        assert "1 findings" in summary
