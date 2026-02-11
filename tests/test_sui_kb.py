"""
Tests for Sui/Move knowledge base content.

Verifies that Sui tips, checklists, and templates load correctly
and are properly filtered by chain.
"""

from pathlib import Path

import pytest

from extensions.knowledge.tip_loader import TipLoader, AuditorTip
from extensions.knowledge.checklist_loader import ChecklistLoader, ChecklistItem
from extensions.knowledge.template_loader import TemplateLoader, PoCTemplate
from extensions.knowledge.manager import KnowledgeBase


KB_DIR = Path(__file__).resolve().parents[1] / "extensions" / "knowledge"


class TestSuiTips:
    """Test Sui/Move-specific auditor tips."""

    def setup_method(self):
        self.loader = TipLoader(KB_DIR / "tips")

    def test_sui_tips_loaded(self):
        tips = self.loader.get_by_chain("sui")
        assert len(tips) >= 10, f"Expected >= 10 Sui tips, got {len(tips)}"

    def test_sui_tips_have_chain_field(self):
        tips = self.loader.get_by_chain("sui")
        for tip in tips:
            assert tip.chain == "sui"

    def test_sui_tips_have_required_fields(self):
        tips = self.loader.get_by_chain("sui")
        for tip in tips:
            assert tip.id, f"Tip missing id: {tip}"
            assert tip.title, f"Tip missing title: {tip.id}"
            assert tip.tip, f"Tip missing tip text: {tip.id}"
            assert tip.priority in ("high", "medium", "low"), f"Invalid priority: {tip.priority}"

    def test_shared_object_tip_exists(self):
        tips = self.loader.get_by_chain("sui")
        shared_tips = [t for t in tips if "shared" in t.title.lower() or "shared" in t.tip.lower()]
        assert len(shared_tips) >= 1, "Expected at least one shared object tip"

    def test_capability_tip_exists(self):
        tips = self.loader.get_by_chain("sui")
        cap_tips = [t for t in tips if "capability" in t.title.lower() or "cap" in t.tip.lower()]
        assert len(cap_tips) >= 1, "Expected at least one capability tip"

    def test_witness_tip_exists(self):
        tips = self.loader.get_by_chain("sui")
        witness_tips = [t for t in tips if "witness" in t.title.lower() or "witness" in t.tip.lower()]
        assert len(witness_tips) >= 1, "Expected at least one witness tip"

    def test_sui_tips_not_in_evm(self):
        """Sui tips should not include EVM tips."""
        sui_tips = self.loader.get_by_chain("sui")
        evm_tips = self.loader.get_by_chain("evm")
        sui_ids = {t.id for t in sui_tips}
        evm_ids = {t.id for t in evm_tips}
        assert sui_ids.isdisjoint(evm_ids), "Sui and EVM tip IDs should not overlap"


class TestSuiChecklists:
    """Test Sui-specific checklist items."""

    def setup_method(self):
        self.loader = ChecklistLoader(KB_DIR)

    def test_sui_checklists_loaded(self):
        items = self.loader.get_by_chain("sui")
        assert len(items) >= 8, f"Expected >= 8 Sui checklist items, got {len(items)}"

    def test_sui_items_have_chain_field(self):
        items = self.loader.get_by_chain("sui")
        for item in items:
            assert item.chain == "sui"

    def test_sui_items_have_required_fields(self):
        items = self.loader.get_by_chain("sui")
        for item in items:
            assert item.id, f"Item missing id"
            assert item.question, f"Item missing question: {item.id}"
            assert item.severity in ("critical", "high", "medium", "low", "informational")

    def test_object_safety_checklist_exists(self):
        items = self.loader.get_by_chain("sui")
        obj_items = [i for i in items if "SUI-OBJ" in i.id]
        assert len(obj_items) >= 3, "Expected at least 3 object safety items"

    def test_capability_patterns_checklist_exists(self):
        items = self.loader.get_by_chain("sui")
        cap_items = [i for i in items if "SUI-CAP" in i.id]
        assert len(cap_items) >= 2, "Expected at least 2 capability pattern items"

    def test_shared_objects_checklist_exists(self):
        items = self.loader.get_by_chain("sui")
        share_items = [i for i in items if "SUI-SHARE" in i.id]
        assert len(share_items) >= 2, "Expected at least 2 shared object items"


class TestSuiTemplates:
    """Test Sui PoC templates."""

    def setup_method(self):
        self.loader = TemplateLoader(KB_DIR / "templates")

    def test_sui_templates_loaded(self):
        templates = self.loader.get_by_chain("sui")
        assert len(templates) >= 3, f"Expected >= 3 Sui templates, got {len(templates)}"

    def test_sui_templates_have_chain_field(self):
        templates = self.loader.get_by_chain("sui")
        for t in templates:
            assert t.chain == "sui"

    def test_shared_object_race_template_exists(self):
        templates = self.loader.get_by_chain("sui")
        race_templates = [t for t in templates if "shared" in t.name.lower() or "race" in t.name.lower()]
        assert len(race_templates) >= 1

    def test_capability_leak_template_exists(self):
        templates = self.loader.get_by_chain("sui")
        cap_templates = [t for t in templates if "capability" in t.name.lower() or "cap" in t.name.lower()]
        assert len(cap_templates) >= 1

    def test_type_confusion_template_exists(self):
        templates = self.loader.get_by_chain("sui")
        type_templates = [t for t in templates if "type" in t.name.lower() or "confusion" in t.name.lower()]
        assert len(type_templates) >= 1

    def test_sui_templates_contain_move_code(self):
        templates = self.loader.get_by_chain("sui")
        for t in templates:
            assert "module " in t.template or "fun " in t.template, \
                f"Template {t.id} doesn't look like Move code"


class TestSuiKBManager:
    """Test the unified KnowledgeBase with Sui chain filter."""

    def setup_method(self):
        self.kb = KnowledgeBase(KB_DIR)

    def test_query_with_sui_filter(self):
        result = self.kb.query("capability", chain="sui")
        for item in result.checklists:
            assert item.chain == "sui"
        for tip in result.tips:
            assert tip.chain == "sui"

    def test_audit_context_with_chain(self):
        ctx = self.kb.get_audit_context("shared object", chain="sui")
        assert isinstance(ctx, str)
