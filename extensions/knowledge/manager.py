"""
Knowledge base manager.

Unified interface for accessing checklists, templates, and tips.
"""

from pathlib import Path
from dataclasses import dataclass
from typing import Any

from .checklist_loader import ChecklistLoader, ChecklistItem
from .template_loader import TemplateLoader, PoCTemplate
from .tip_loader import TipLoader, AuditorTip


@dataclass
class KnowledgeQuery:
    """Result of a knowledge base query."""
    checklists: list[ChecklistItem]
    templates: list[PoCTemplate]
    tips: list[AuditorTip]

    def to_context(self) -> str:
        """Convert to context string for LLM prompts."""
        parts = []

        if self.checklists:
            parts.append("## Relevant Checklist Items")
            for item in self.checklists[:10]:
                parts.append(f"- [{item.id}] {item.question}")
                if item.remediation:
                    parts.append(f"  Remediation: {item.remediation[:200]}...")

        if self.tips:
            parts.append("\n## Auditor Tips")
            for tip in self.tips[:5]:
                parts.append(f"- **{tip.title}**: {tip.tip}")

        if self.templates:
            parts.append("\n## Available PoC Templates")
            for template in self.templates[:3]:
                parts.append(f"- {template.name}: {template.description}")

        return "\n".join(parts)


class KnowledgeBase:
    """Unified knowledge base for smart contract security auditing."""

    def __init__(self, base_dir: Path | None = None):
        """Initialize knowledge base.

        Args:
            base_dir: Path to knowledge base directory
        """
        if base_dir is None:
            base_dir = Path(__file__).parent

        self.base_dir = base_dir
        self.checklists = ChecklistLoader(base_dir)
        self.templates = TemplateLoader(base_dir / "templates")
        self.tips = TipLoader(base_dir / "tips")

    def query(
        self,
        search_term: str,
        include_checklists: bool = True,
        include_templates: bool = True,
        include_tips: bool = True,
        chain: str | None = None,
    ) -> KnowledgeQuery:
        """Query the knowledge base.

        Args:
            search_term: Search query
            include_checklists: Include checklist results
            include_templates: Include template results
            include_tips: Include tip results
            chain: Optional chain filter (e.g., "evm", "solana", "sui")

        Returns:
            KnowledgeQuery with matching items
        """
        checklists = []
        templates = []
        tips = []

        if include_checklists:
            checklists = self.checklists.search(search_term)

        if include_templates:
            templates = self.templates.get_by_vulnerability(search_term)

        if include_tips:
            tips = self.tips.search(search_term)

        # Filter by chain if specified
        if chain:
            chain_lower = chain.lower()
            if checklists:
                checklists = [c for c in checklists if c.chain.lower() == chain_lower]
            if templates:
                templates = [t for t in templates if t.chain.lower() == chain_lower]
            if tips:
                tips = [t for t in tips if t.chain.lower() == chain_lower]

        return KnowledgeQuery(
            checklists=checklists,
            templates=templates,
            tips=tips,
        )

    def get_audit_context(self, vulnerability_type: str, chain: str | None = None) -> str:
        """Get context for auditing a specific vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability to get context for
            chain: Optional chain filter (e.g., "evm", "solana", "sui")

        Returns a formatted string with relevant checklists, tips, and templates
        suitable for including in LLM prompts.
        """
        query = self.query(vulnerability_type, chain=chain)
        return query.to_context()

    def get_protocol_context(self, protocol_type: str, chain: str | None = None) -> str:
        """Get context for auditing a specific protocol type (lending, AMM, etc.).

        Args:
            protocol_type: Type of protocol (e.g., "lending", "amm", "vault")
            chain: Optional chain filter (e.g., "evm", "solana", "sui")
        """
        # Map protocol types to relevant vulnerability categories
        protocol_vulns = {
            "lending": ["oracle", "liquidation", "interest", "collateral", "flash-loan"],
            "amm": ["slippage", "manipulation", "liquidity", "swap", "MEV"],
            "vault": ["inflation", "ERC4626", "deposit", "withdraw", "share"],
            "governance": ["voting", "proposal", "timelock", "flash-loan"],
            "staking": ["reward", "stake", "claim", "timing"],
            "bridge": ["message", "relay", "cross-chain", "verification"],
        }

        vulns = protocol_vulns.get(protocol_type.lower(), [protocol_type])

        all_checklists = []
        all_tips = []
        all_templates = []

        for vuln in vulns:
            query = self.query(vuln, chain=chain)
            all_checklists.extend(query.checklists)
            all_tips.extend(query.tips)
            all_templates.extend(query.templates)

        # Deduplicate
        seen_ids = set()
        unique_checklists = []
        for item in all_checklists:
            if item.id not in seen_ids:
                seen_ids.add(item.id)
                unique_checklists.append(item)

        seen_ids = set()
        unique_tips = []
        for tip in all_tips:
            if tip.id not in seen_ids:
                seen_ids.add(tip.id)
                unique_tips.append(tip)

        return KnowledgeQuery(
            checklists=unique_checklists[:20],
            templates=all_templates[:5],
            tips=unique_tips[:10],
        ).to_context()

    def get_poc_template(self, vulnerability_type: str, **kwargs) -> str | None:
        """Get a rendered PoC template for a vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability
            **kwargs: Placeholder values for template

        Returns:
            Rendered template string or None
        """
        templates = self.templates.get_by_vulnerability(vulnerability_type)
        if not templates:
            return None

        return self.templates.render(templates[0].id, **kwargs)

    def stats(self) -> dict[str, Any]:
        """Get knowledge base statistics."""
        return {
            "checklists": self.checklists.stats(),
            "templates": len(self.templates.list_all()),
            "tips": len(self.tips.get_all()),
        }

    def list_categories(self) -> dict[str, list[str]]:
        """List all available categories."""
        return {
            "checklist_categories": self.checklists.get_categories(),
            "template_types": [t.vulnerability_type for t in self.templates.list_all()],
            "tip_categories": list(set(t.category for t in self.tips.get_all())),
        }
