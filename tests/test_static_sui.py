"""
Tests for Sui/Move static analysis runners.

Tests MoveProverRunner and SuiMoveLintRunner with mocked subprocess output.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from extensions.static.move_prover_runner import MoveProverRunner, MoveProverFinding
from extensions.static.sui_move_lint_runner import SuiMoveLintRunner, SuiMoveLintFinding
from extensions.static.pipeline import StaticAnalysisPipeline


class TestMoveProverFinding:
    """Test MoveProverFinding dataclass and hypothesis conversion."""

    def test_to_hypothesis_error(self):
        finding = MoveProverFinding(
            property="arithmetic-overflow",
            status="error",
            file_path="sources/vault.move",
            line=42,
            message="arithmetic overflow detected in deposit function",
        )
        hyp = finding.to_hypothesis()

        assert "Move Prover" in hyp["title"]
        assert "arithmetic-overflow" in hyp["vulnerability_type"]
        assert hyp["confidence"] == 0.9  # error status
        assert hyp["properties"]["source_tool"] == "move-prover"
        assert "sources/vault.move" in hyp["properties"]["source_files"]

    def test_to_hypothesis_failure(self):
        finding = MoveProverFinding(
            property="postcondition-failure",
            status="failure",
            file_path="sources/token.move",
            line=100,
            message="verification failed for ensures clause",
        )
        hyp = finding.to_hypothesis()

        assert hyp["confidence"] == 0.85  # failure status

    def test_to_hypothesis_timeout(self):
        finding = MoveProverFinding(
            property="verification-timeout",
            status="timeout",
            message="prover timeout",
        )
        hyp = finding.to_hypothesis()

        assert hyp["confidence"] == 0.5  # timeout status

    def test_to_hypothesis_minimal(self):
        finding = MoveProverFinding(
            property="test",
            status="error",
        )
        hyp = finding.to_hypothesis()
        assert "title" in hyp
        assert "severity" in hyp


class TestMoveProverRunner:
    """Test MoveProverRunner with mocked subprocess."""

    def test_is_available_when_installed(self):
        with patch("shutil.which", return_value="/usr/bin/sui"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="sui 1.20.0",
                    stderr="",
                )
                runner = MoveProverRunner()
                available, version = runner.is_available()
                assert available is True
                assert "1.20.0" in version

    def test_is_available_when_not_installed(self):
        with patch("shutil.which", return_value=None):
            runner = MoveProverRunner()
            available, msg = runner.is_available()
            assert available is False

    def test_run_parses_error_output(self):
        """Test parsing Move Prover error output."""
        sample_output = """
error: [arithmetic-overflow] at sources/vault.move:42: arithmetic overflow detected
error: verification failed for postcondition
  --> sources/token.move:100
"""
        with patch.object(MoveProverRunner, "is_available", return_value=(True, "1.20.0")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1,
                    stdout="",
                    stderr=sample_output,
                )
                runner = MoveProverRunner()
                findings, metadata = runner.run(Path("/tmp/test-move"))

                assert metadata["success"] is True
                assert len(findings) >= 1

    def test_run_handles_clean_verification(self):
        """No findings when verification passes."""
        with patch.object(MoveProverRunner, "is_available", return_value=(True, "1.20.0")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="Verification successful\n",
                    stderr="",
                )
                runner = MoveProverRunner()
                findings, metadata = runner.run(Path("/tmp/test-move"))

                assert metadata["success"] is True
                assert len(findings) == 0

    def test_run_handles_timeout(self):
        """Runner handles subprocess timeout gracefully."""
        import subprocess

        with patch.object(MoveProverRunner, "is_available", return_value=(True, "1.20.0")):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("sui", 300)):
                runner = MoveProverRunner()
                findings, metadata = runner.run(Path("/tmp/test-move"))

                assert len(findings) == 0
                assert "timed out" in metadata["error"].lower()


class TestSuiMoveLintFinding:
    """Test SuiMoveLintFinding dataclass and hypothesis conversion."""

    def test_to_hypothesis(self):
        finding = SuiMoveLintFinding(
            lint_id="self_transfer",
            message="self_transfer: Unnecessary self-transfer detected",
            file_path="sources/marketplace.move",
            line=55,
            severity="Medium",
        )
        hyp = finding.to_hypothesis()

        assert "Move Lint" in hyp["title"]
        assert "self_transfer" in hyp["vulnerability_type"]
        assert hyp["severity"] == "medium"
        assert hyp["confidence"] == 0.7
        assert hyp["properties"]["source_tool"] == "sui-move-lint"

    def test_to_hypothesis_high_severity(self):
        finding = SuiMoveLintFinding(
            lint_id="missing_key",
            message="Missing key ability on object",
            severity="High",
        )
        hyp = finding.to_hypothesis()
        assert hyp["severity"] == "high"
        assert hyp["confidence"] == 0.85

    def test_to_hypothesis_low_severity(self):
        finding = SuiMoveLintFinding(
            lint_id="unused_variable",
            message="Unused variable x",
            severity="Low",
        )
        hyp = finding.to_hypothesis()
        assert hyp["severity"] == "low"
        assert hyp["confidence"] == 0.6


class TestSuiMoveLintRunner:
    """Test SuiMoveLintRunner with mocked subprocess."""

    def test_is_available_when_installed(self):
        with patch("shutil.which", return_value="/usr/bin/sui"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="sui 1.20.0",
                    stderr="",
                )
                runner = SuiMoveLintRunner()
                available, version = runner.is_available()
                assert available is True

    def test_is_available_when_not_installed(self):
        with patch("shutil.which", return_value=None):
            runner = SuiMoveLintRunner()
            available, msg = runner.is_available()
            assert available is False

    def test_run_parses_lint_output(self):
        """Test parsing sui move build --lint warnings."""
        sample_output = """
warning[W01001]: self_transfer
  --> sources/marketplace.move:55:9
   |
55 |         transfer::public_transfer(nft, tx_context::sender(ctx));
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Unnecessary self-transfer

warning[W01002]: unused_variable
  --> sources/utils.move:12:13
   |
12 |         let x = 42;
   |             ^ Unused variable
"""
        with patch.object(SuiMoveLintRunner, "is_available", return_value=(True, "1.20.0")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="",
                    stderr=sample_output,
                )
                runner = SuiMoveLintRunner()
                findings, metadata = runner.run(Path("/tmp/test-move"))

                assert metadata["success"] is True
                assert len(findings) >= 2

    def test_run_handles_clean_output(self):
        """No findings when lint passes cleanly."""
        with patch.object(SuiMoveLintRunner, "is_available", return_value=(True, "1.20.0")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="BUILDING my_module\n",
                    stderr="",
                )
                runner = SuiMoveLintRunner()
                findings, metadata = runner.run(Path("/tmp/test-move"))

                assert metadata["success"] is True
                assert len(findings) == 0


class TestSuiPipeline:
    """Test the static analysis pipeline with Sui chain."""

    def test_sui_pipeline_selects_correct_runners(self):
        pipeline = StaticAnalysisPipeline(chain_id="sui")
        assert "move-prover" in pipeline.runners
        assert "sui-move-lint" in pipeline.runners
        assert "slither" not in pipeline.runners
        assert "soteria" not in pipeline.runners

    def test_aptos_pipeline_selects_correct_runners(self):
        pipeline = StaticAnalysisPipeline(chain_id="aptos")
        assert "move-prover" in pipeline.runners
        assert "sui-move-lint" in pipeline.runners

    def test_pipeline_metadata_includes_chain(self):
        """Pipeline metadata should include chain_id."""
        pipeline = StaticAnalysisPipeline(chain_id="sui")
        # Mock all runners to be unavailable
        for name, runner in pipeline.runners.items():
            runner.is_available = MagicMock(return_value=(False, "not installed"))

        result = pipeline.run(Path("/tmp/test"))
        assert result.metadata["chain_id"] == "sui"
