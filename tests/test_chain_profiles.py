"""
Tests for the chain profile system.

Covers profile creation, auto-detection, registry, and default behavior.
"""

import tempfile
from pathlib import Path

import pytest

from analysis.chain_profiles import (
    ChainProfile,
    CHAIN_PROFILES,
    get_profile,
    detect_chain_from_files,
    evm_profile,
    solana_profile,
    sui_profile,
    aptos_profile,
)


class TestProfileCreation:
    """Test that each profile factory returns a valid ChainProfile."""

    @pytest.mark.parametrize("chain_id,factory", [
        ("evm", evm_profile),
        ("solana", solana_profile),
        ("sui", sui_profile),
        ("aptos", aptos_profile),
    ])
    def test_factory_returns_chain_profile(self, chain_id, factory):
        profile = factory()
        assert isinstance(profile, ChainProfile)
        assert profile.chain_id == chain_id

    @pytest.mark.parametrize("chain_id,factory", [
        ("evm", evm_profile),
        ("solana", solana_profile),
        ("sui", sui_profile),
        ("aptos", aptos_profile),
    ])
    def test_profile_has_required_fields(self, chain_id, factory):
        profile = factory()
        assert profile.display_name
        assert len(profile.languages) > 0
        assert len(profile.file_extensions) > 0
        assert profile.module_term
        assert profile.module_term_plural
        assert profile.function_term
        assert len(profile.access_control_patterns) > 0
        assert profile.state_term
        assert len(profile.vulnerability_categories) >= 10
        assert len(profile.graph_type_suggestions) > 0
        assert profile.code_language
        assert len(profile.static_tools) > 0
        assert len(profile.project_root_markers) > 0
        assert len(profile.annotation_examples) > 0

    def test_evm_profile_specifics(self):
        p = evm_profile()
        assert "solidity" in p.languages
        assert ".sol" in p.file_extensions
        assert p.module_term == "contract"
        assert p.code_language == "solidity"
        assert "slither" in p.static_tools
        assert "foundry.toml" in p.project_root_markers
        # EVM supplements should be empty (default behavior)
        assert p.agent_prompt_supplement == ""
        assert p.strategist_prompt_supplement == ""
        assert p.graph_builder_supplement == ""

    def test_solana_profile_specifics(self):
        p = solana_profile()
        assert "rust" in p.languages
        assert ".rs" in p.file_extensions
        assert p.module_term == "program"
        assert p.code_language == "rust"
        assert "soteria" in p.static_tools
        assert "Anchor.toml" in p.project_root_markers
        assert "SOLANA" in p.agent_prompt_supplement
        assert "SOLANA" in p.strategist_prompt_supplement
        assert len(p.graph_builder_supplement) > 0

    def test_sui_profile_specifics(self):
        p = sui_profile()
        assert "move" in p.languages
        assert ".move" in p.file_extensions
        assert p.module_term == "module"
        assert p.code_language == "move"
        assert "Move.toml" in p.project_root_markers
        assert "SUI" in p.agent_prompt_supplement or "Sui" in p.agent_prompt_supplement
        assert len(p.strategist_prompt_supplement) > 0

    def test_aptos_profile_specifics(self):
        p = aptos_profile()
        assert "move" in p.languages
        assert ".move" in p.file_extensions
        assert p.module_term == "module"
        assert p.code_language == "move"
        assert "APTOS" in p.agent_prompt_supplement or "Aptos" in p.agent_prompt_supplement


class TestGetProfile:
    """Test the get_profile registry function."""

    def test_get_all_valid_profiles(self):
        for chain_id in ["evm", "solana", "sui", "aptos"]:
            profile = get_profile(chain_id)
            assert profile.chain_id == chain_id

    def test_get_unknown_profile_raises(self):
        with pytest.raises(ValueError, match="Unknown chain"):
            get_profile("bitcoin")

    def test_registry_has_all_chains(self):
        assert set(CHAIN_PROFILES.keys()) == {"evm", "solana", "sui", "aptos"}

    def test_get_profile_returns_fresh_instance(self):
        """Each call should return a new instance."""
        p1 = get_profile("evm")
        p2 = get_profile("evm")
        assert p1 is not p2
        assert p1.chain_id == p2.chain_id


class TestAutoDetection:
    """Test chain auto-detection from project files."""

    def test_detect_anchor_toml(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Anchor.toml").write_text("[programs]\n")
            assert detect_chain_from_files(d) == "solana"

    def test_detect_move_toml_sui(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Move.toml").write_text(
                '[package]\nname = "my_module"\n\n[dependencies]\nSui = { git = "https://github.com/MystenLabs/sui.git" }\n'
            )
            assert detect_chain_from_files(d) == "sui"

    def test_detect_move_toml_aptos(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Move.toml").write_text(
                '[package]\nname = "my_module"\n\n[dependencies]\nAptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git" }\n'
            )
            assert detect_chain_from_files(d) == "aptos"

    def test_detect_move_toml_default_sui(self):
        """Bare Move.toml with no sui/aptos keywords defaults to sui."""
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Move.toml").write_text('[package]\nname = "test"\n')
            assert detect_chain_from_files(d) == "sui"

    def test_detect_foundry_toml(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "foundry.toml").write_text("[profile.default]\n")
            assert detect_chain_from_files(d) == "evm"

    def test_detect_hardhat_config(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "hardhat.config.js").write_text("module.exports = {}")
            assert detect_chain_from_files(d) == "evm"

    def test_detect_cargo_toml_with_anchor(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Cargo.toml").write_text(
                '[dependencies]\nanchor-lang = "0.29"\n'
            )
            assert detect_chain_from_files(d) == "solana"

    def test_detect_by_sol_files(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Contract.sol").write_text("pragma solidity ^0.8.0;")
            assert detect_chain_from_files(d) == "evm"

    def test_detect_by_move_files(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "module.move").write_text("module my_module {}")
            assert detect_chain_from_files(d) == "sui"

    def test_detect_by_rs_files(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "lib.rs").write_text("use anchor_lang::prelude::*;")
            assert detect_chain_from_files(d) == "solana"

    def test_detect_empty_dir_defaults_evm(self):
        with tempfile.TemporaryDirectory() as d:
            assert detect_chain_from_files(d) == "evm"

    def test_detect_nonexistent_path_defaults_evm(self):
        assert detect_chain_from_files("/nonexistent/path/12345") == "evm"

    def test_anchor_toml_takes_priority_over_cargo(self):
        """Anchor.toml should be detected as Solana even if Cargo.toml also exists."""
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Anchor.toml").write_text("[programs]\n")
            (Path(d) / "Cargo.toml").write_text('[package]\nname = "test"\n')
            assert detect_chain_from_files(d) == "solana"
