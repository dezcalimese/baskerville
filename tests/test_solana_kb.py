"""
Tests for Solana knowledge base content.

Verifies that Solana tips, checklists, and templates load correctly
and are properly filtered by chain.
"""

from pathlib import Path

import pytest

from extensions.knowledge.tip_loader import TipLoader, AuditorTip
from extensions.knowledge.checklist_loader import ChecklistLoader, ChecklistItem
from extensions.knowledge.template_loader import TemplateLoader, PoCTemplate
from extensions.knowledge.manager import KnowledgeBase


KB_DIR = Path(__file__).resolve().parents[1] / "extensions" / "knowledge"


class TestSolanaTips:
    """Test Solana-specific auditor tips."""

    def setup_method(self):
        self.loader = TipLoader(KB_DIR / "tips")

    def test_solana_tips_loaded(self):
        tips = self.loader.get_by_chain("solana")
        assert len(tips) >= 10, f"Expected >= 10 Solana tips, got {len(tips)}"

    def test_solana_tips_have_chain_field(self):
        tips = self.loader.get_by_chain("solana")
        for tip in tips:
            assert tip.chain == "solana"

    def test_solana_tips_have_required_fields(self):
        tips = self.loader.get_by_chain("solana")
        for tip in tips:
            assert tip.id, f"Tip missing id: {tip}"
            assert tip.title, f"Tip missing title: {tip.id}"
            assert tip.tip, f"Tip missing tip text: {tip.id}"
            assert tip.priority in ("high", "medium", "low"), f"Invalid priority: {tip.priority}"

    def test_signer_check_tip_exists(self):
        tips = self.loader.get_by_chain("solana")
        signer_tips = [t for t in tips if "signer" in t.title.lower() or "signer" in t.tip.lower()]
        assert len(signer_tips) >= 1, "Expected at least one signer check tip"

    def test_cpi_tip_exists(self):
        tips = self.loader.get_by_chain("solana")
        cpi_tips = [t for t in tips if "cpi" in t.title.lower() or "cpi" in t.tip.lower()]
        assert len(cpi_tips) >= 1, "Expected at least one CPI tip"

    def test_pda_tip_exists(self):
        tips = self.loader.get_by_chain("solana")
        pda_tips = [t for t in tips if "pda" in t.title.lower() or "pda" in t.tip.lower()]
        assert len(pda_tips) >= 1, "Expected at least one PDA tip"

    def test_evm_tips_not_in_solana(self):
        """Solana tips should not include EVM tips."""
        solana_tips = self.loader.get_by_chain("solana")
        evm_tips = self.loader.get_by_chain("evm")
        solana_ids = {t.id for t in solana_tips}
        evm_ids = {t.id for t in evm_tips}
        assert solana_ids.isdisjoint(evm_ids), "Solana and EVM tip IDs should not overlap"


class TestSolanaChecklists:
    """Test Solana-specific checklist items."""

    def setup_method(self):
        self.loader = ChecklistLoader(KB_DIR)

    def test_solana_checklists_loaded(self):
        items = self.loader.get_by_chain("solana")
        assert len(items) >= 8, f"Expected >= 8 Solana checklist items, got {len(items)}"

    def test_solana_items_have_chain_field(self):
        items = self.loader.get_by_chain("solana")
        for item in items:
            assert item.chain == "solana"

    def test_solana_items_have_required_fields(self):
        items = self.loader.get_by_chain("solana")
        for item in items:
            assert item.id, f"Item missing id"
            assert item.question, f"Item missing question: {item.id}"
            assert item.severity in ("critical", "high", "medium", "low", "informational")

    def test_account_validation_checklist_exists(self):
        items = self.loader.get_by_chain("solana")
        av_items = [i for i in items if "SOL-AV" in i.id]
        assert len(av_items) >= 3, "Expected at least 3 account validation items"

    def test_cpi_security_checklist_exists(self):
        items = self.loader.get_by_chain("solana")
        cpi_items = [i for i in items if "SOL-CPI" in i.id]
        assert len(cpi_items) >= 2, "Expected at least 2 CPI security items"

    def test_signer_auth_checklist_exists(self):
        items = self.loader.get_by_chain("solana")
        auth_items = [i for i in items if "SOL-AUTH" in i.id]
        assert len(auth_items) >= 2, "Expected at least 2 signer authorization items"


class TestSolanaTemplates:
    """Test Solana PoC templates."""

    def setup_method(self):
        self.loader = TemplateLoader(KB_DIR / "templates")

    def test_solana_templates_loaded(self):
        templates = self.loader.get_by_chain("solana")
        assert len(templates) >= 3, f"Expected >= 3 Solana templates, got {len(templates)}"

    def test_solana_templates_have_chain_field(self):
        templates = self.loader.get_by_chain("solana")
        for t in templates:
            assert t.chain == "solana"

    def test_missing_signer_template_exists(self):
        templates = self.loader.get_by_chain("solana")
        signer_templates = [t for t in templates if "signer" in t.name.lower()]
        assert len(signer_templates) >= 1

    def test_cpi_reentrancy_template_exists(self):
        templates = self.loader.get_by_chain("solana")
        cpi_templates = [t for t in templates if "cpi" in t.name.lower()]
        assert len(cpi_templates) >= 1

    def test_pda_seed_template_exists(self):
        templates = self.loader.get_by_chain("solana")
        pda_templates = [t for t in templates if "pda" in t.name.lower() or "seed" in t.name.lower()]
        assert len(pda_templates) >= 1

    def test_solana_templates_contain_rust_code(self):
        templates = self.loader.get_by_chain("solana")
        for t in templates:
            assert "fn " in t.template or "use " in t.template, \
                f"Template {t.id} doesn't look like Rust code"


class TestSolanaKBManager:
    """Test the unified KnowledgeBase with Solana chain filter."""

    def setup_method(self):
        self.kb = KnowledgeBase(KB_DIR)

    def test_query_with_solana_filter(self):
        result = self.kb.query("signer", chain="solana")
        # Should only return Solana items
        for item in result.checklists:
            assert item.chain == "solana"
        for tip in result.tips:
            assert tip.chain == "solana"

    def test_audit_context_with_chain(self):
        ctx = self.kb.get_audit_context("signer", chain="solana")
        assert isinstance(ctx, str)
