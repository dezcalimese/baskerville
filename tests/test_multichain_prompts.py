"""
Tests for multi-chain prompt adaptation.

Verifies that chain profiles produce correct prompt content for agent, strategist,
and graph builder, and that EVM behavior is unchanged.

Note: We test the profiles and their prompt supplements directly rather than
instantiating the full Agent/Strategist/GraphBuilder (which have heavy deps).
"""

import pytest

from analysis.chain_profiles import (
    get_profile,
    evm_profile,
    solana_profile,
    sui_profile,
    aptos_profile,
)


class TestAgentPromptSupplements:
    """Test that agent prompt supplements contain chain-appropriate content."""

    def test_evm_agent_supplement_empty(self):
        """EVM default has no supplement (original behavior preserved)."""
        p = evm_profile()
        assert p.agent_prompt_supplement == ""

    def test_solana_agent_supplement_content(self):
        p = solana_profile()
        supplement = p.agent_prompt_supplement
        assert len(supplement) > 100
        assert "account validation" in supplement.lower()
        assert "CPI" in supplement
        assert "PDA" in supplement
        assert "signer" in supplement.lower()

    def test_sui_agent_supplement_content(self):
        p = sui_profile()
        supplement = p.agent_prompt_supplement
        assert len(supplement) > 100
        assert "object ownership" in supplement.lower()
        assert "capability" in supplement.lower()
        assert "one-time witness" in supplement.lower() or "OTW" in supplement
        assert "shared object" in supplement.lower()

    def test_aptos_agent_supplement_content(self):
        p = aptos_profile()
        supplement = p.agent_prompt_supplement
        assert len(supplement) > 100
        assert "resource" in supplement.lower()
        assert "signer" in supplement.lower()


class TestStrategistPromptSupplements:
    """Test that strategist prompt supplements contain chain-appropriate priorities."""

    def test_evm_strategist_supplement_empty(self):
        p = evm_profile()
        assert p.strategist_prompt_supplement == ""

    def test_solana_strategist_supplement_content(self):
        p = solana_profile()
        supplement = p.strategist_prompt_supplement
        assert "signer" in supplement.lower()
        assert "CPI" in supplement
        assert "PDA" in supplement
        assert "overflow" in supplement.lower()

    def test_sui_strategist_supplement_content(self):
        p = sui_profile()
        supplement = p.strategist_prompt_supplement
        assert "shared object" in supplement.lower()
        assert "capability" in supplement.lower()
        assert "witness" in supplement.lower()
        assert "generics" in supplement.lower() or "type confusion" in supplement.lower()

    def test_aptos_strategist_supplement_content(self):
        p = aptos_profile()
        supplement = p.strategist_prompt_supplement
        assert "signer" in supplement.lower()
        assert "resource" in supplement.lower()
        assert "capability" in supplement.lower()


class TestGraphBuilderSupplements:
    """Test that graph builder supplements contain chain-appropriate graph types."""

    def test_evm_graph_builder_supplement_empty(self):
        p = evm_profile()
        assert p.graph_builder_supplement == ""

    def test_evm_graph_type_suggestions(self):
        """EVM graph type suggestions contain EVM-specific graphs."""
        p = evm_profile()
        suggestions = p.graph_type_suggestions
        assert any("Reentrancy" in s for s in suggestions)
        assert any("AuthorizationMap" in s for s in suggestions)
        assert any("UpgradeLifecycle" in s for s in suggestions)

    def test_solana_graph_builder_supplement_content(self):
        p = solana_profile()
        supplement = p.graph_builder_supplement
        assert "AccountValidation" in supplement
        assert "CPIGraph" in supplement
        assert "SignerAuthority" in supplement
        assert "PDASeedMap" in supplement
        assert "LamportFlow" in supplement

    def test_sui_graph_builder_supplement_content(self):
        p = sui_profile()
        supplement = p.graph_builder_supplement
        assert "ObjectOwnership" in supplement
        assert "CapabilityFlow" in supplement
        assert "DynamicFieldGraph" in supplement
        assert "WitnessPatternMap" in supplement
        assert "SharedObjectAccess" in supplement

    def test_aptos_graph_builder_supplement_content(self):
        p = aptos_profile()
        supplement = p.graph_builder_supplement
        assert "ResourceFlow" in supplement
        assert "CapabilityFlow" in supplement
        assert "TableAccess" in supplement
        assert "CoinFlow" in supplement


class TestAnnotationExamples:
    """Test that annotation examples are chain-appropriate."""

    def test_evm_annotations(self):
        p = evm_profile()
        annotations = p.annotation_examples
        assert "nonReentrant" in annotations
        assert "only owner" in annotations
        assert "emits Transfer" in annotations

    def test_solana_annotations(self):
        p = solana_profile()
        annotations = p.annotation_examples
        assert any("signer" in a.lower() for a in annotations)
        assert any("CPI" in a or "cpi" in a.lower() for a in annotations)
        assert any("PDA" in a or "pda" in a.lower() for a in annotations)

    def test_sui_annotations(self):
        p = sui_profile()
        annotations = p.annotation_examples
        assert any("shared" in a.lower() for a in annotations)
        assert any("capability" in a.lower() for a in annotations)
        assert any("witness" in a.lower() for a in annotations)


class TestVulnerabilityCategories:
    """Test that vulnerability categories cover chain-specific concerns."""

    def test_evm_categories(self):
        cats = evm_profile().vulnerability_categories
        assert any("reentrancy" in c.lower() for c in cats)
        assert any("oracle" in c.lower() for c in cats)
        assert any("flash" in c.lower() for c in cats)
        assert any("proxy" in c.lower() or "storage collision" in c.lower() for c in cats)

    def test_solana_categories(self):
        cats = solana_profile().vulnerability_categories
        assert any("signer" in c.lower() for c in cats)
        assert any("owner" in c.lower() for c in cats)
        assert any("pda" in c.lower() for c in cats)
        assert any("cpi" in c.lower() for c in cats)
        assert any("overflow" in c.lower() for c in cats)

    def test_sui_categories(self):
        cats = sui_profile().vulnerability_categories
        assert any("shared" in c.lower() for c in cats)
        assert any("capability" in c.lower() for c in cats)
        assert any("witness" in c.lower() for c in cats)
        assert any("generic" in c.lower() for c in cats)

    def test_aptos_categories(self):
        cats = aptos_profile().vulnerability_categories
        assert any("resource" in c.lower() for c in cats)
        assert any("signer" in c.lower() for c in cats)
        assert any("table" in c.lower() for c in cats)


class TestModuleTerminology:
    """Test that terminology is correct for each chain."""

    def test_evm_terms(self):
        p = evm_profile()
        assert p.module_term == "contract"
        assert p.module_term_plural == "contracts"
        assert p.function_term == "function"
        assert p.state_term == "storage"

    def test_solana_terms(self):
        p = solana_profile()
        assert p.module_term == "program"
        assert p.module_term_plural == "programs"
        assert p.function_term == "instruction handler"
        assert p.state_term == "account data"

    def test_sui_terms(self):
        p = sui_profile()
        assert p.module_term == "module"
        assert p.module_term_plural == "modules"
        assert p.function_term == "entry function"
        assert p.state_term == "shared objects"

    def test_aptos_terms(self):
        p = aptos_profile()
        assert p.module_term == "module"
        assert p.module_term_plural == "modules"
        assert p.function_term == "entry function"
        assert p.state_term == "global storage resources"


class TestPromptInterpolation:
    """Test that profile values can be interpolated into prompt templates."""

    def test_module_term_in_system_prompt(self):
        """Verify that module_term_plural can be used in f-strings."""
        for chain_id in ["evm", "solana", "sui", "aptos"]:
            p = get_profile(chain_id)
            prompt = f"You are analyzing {p.module_term_plural}."
            assert p.module_term_plural in prompt

    def test_vuln_categories_as_string(self):
        """Verify vulnerability categories can be joined for prompts."""
        for chain_id in ["evm", "solana", "sui", "aptos"]:
            p = get_profile(chain_id)
            cats_str = ", ".join(p.vulnerability_categories)
            assert len(cats_str) > 50

    def test_annotation_examples_in_prompt(self):
        """Verify annotation examples can be formatted for prompts."""
        for chain_id in ["evm", "solana", "sui", "aptos"]:
            p = get_profile(chain_id)
            examples = ", ".join(f'"{ex}"' for ex in p.annotation_examples[:5])
            assert len(examples) > 10
