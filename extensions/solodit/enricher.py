"""
Hypothesis enricher using Solodit data.

Cross-references Hound hypotheses against Solodit's vulnerability database
to add historical context, similar findings, and remediation guidance.
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Any

from .client import SoloditClient, SoloditFinding
from .cache import SoloditCache


@dataclass
class EnrichmentResult:
    """Result of enriching a hypothesis with Solodit data."""

    hypothesis_id: str
    similar_findings: list[SoloditFinding]
    checklist_matches: list[dict]
    confidence_adjustment: float
    context_summary: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "similar_findings": [
                {
                    "title": f.title,
                    "slug": f.slug,
                    "impact": f.impact,
                    "severity": f.severity,
                    "url": f.url,
                    "firm": f.firm_name,
                    "quality": f.quality_score,
                }
                for f in self.similar_findings
            ],
            "checklist_matches": self.checklist_matches,
            "confidence_adjustment": self.confidence_adjustment,
            "context_summary": self.context_summary,
        }


class HypothesisEnricher:
    """Enriches Hound hypotheses with Solodit context."""

    # Map vulnerability types to Solodit tags
    VULNERABILITY_TAGS = {
        "reentrancy": "Reentrancy",
        "access-control": "Access Control",
        "oracle": "Oracle",
        "flash-loan": "Flash Loan",
        "integer": "Integer Overflow/Underflow",
        "front-running": "Front-running",
        "dos": "DOS",
        "price-manipulation": "Price Manipulation",
        "logic": "Logic Error",
        "griefing": "Griefing",
    }

    # Keywords to extract from vulnerability types
    VULNERABILITY_KEYWORDS = {
        "reentrancy": ["reentrancy", "reentrant", "callback", "external call"],
        "access-control": ["access control", "permission", "unauthorized", "owner", "admin"],
        "oracle": ["oracle", "price", "chainlink", "twap", "manipulation"],
        "flash-loan": ["flash loan", "flash", "atomic", "borrow"],
        "integer": ["overflow", "underflow", "arithmetic", "integer"],
        "front-running": ["front-run", "frontrun", "mev", "sandwich"],
        "dos": ["denial of service", "dos", "gas limit", "loop"],
        "signature": ["signature", "ecrecover", "replay", "nonce"],
        "storage": ["storage", "collision", "slot", "proxy"],
        "logic": ["logic", "state", "condition", "check"],
    }

    def __init__(
        self,
        client: SoloditClient | None = None,
        cache: SoloditCache | None = None,
    ):
        """Initialize enricher.

        Args:
            client: Solodit API client
            cache: Cache instance for storing results
        """
        self.client = client or SoloditClient()
        self.cache = cache or SoloditCache()

    def _extract_keywords(self, hypothesis: dict) -> list[str]:
        """Extract search keywords from a hypothesis."""
        keywords = set()

        # Get from vulnerability type
        vuln_type = hypothesis.get("vulnerability_type", "").lower()
        for category, terms in self.VULNERABILITY_KEYWORDS.items():
            if any(term in vuln_type for term in terms):
                keywords.add(category)
                break

        # Get from title
        title = hypothesis.get("title", "").lower()
        for category, terms in self.VULNERABILITY_KEYWORDS.items():
            if any(term in title for term in terms):
                keywords.add(category)

        # Get from description (first 500 chars)
        description = hypothesis.get("description", "")[:500].lower()
        for category, terms in self.VULNERABILITY_KEYWORDS.items():
            if any(term in description for term in terms):
                keywords.add(category)

        # Add vulnerability type itself if not empty
        if vuln_type and vuln_type not in keywords:
            # Clean up the type for searching
            clean_type = re.sub(r'[_-]', ' ', vuln_type)
            keywords.add(clean_type)

        return list(keywords) if keywords else ["vulnerability"]

    def _extract_tags(self, hypothesis: dict) -> list[str]:
        """Extract Solodit tags from a hypothesis."""
        tags = []
        keywords = self._extract_keywords(hypothesis)

        for kw in keywords:
            if kw in self.VULNERABILITY_TAGS:
                tags.append(self.VULNERABILITY_TAGS[kw])

        return tags

    def _calculate_confidence_adjustment(
        self,
        hypothesis: dict,
        similar_findings: list[SoloditFinding],
    ) -> float:
        """Calculate confidence adjustment based on similar findings.

        Returns a value to add to the hypothesis confidence (can be negative).
        """
        if not similar_findings:
            return 0.0

        # More similar findings = higher confidence
        count_boost = min(len(similar_findings) * 0.02, 0.1)  # Max +0.1 from count

        # High impact similar findings = higher confidence
        high_impact_count = sum(
            1 for f in similar_findings
            if f.impact in ["HIGH"]
        )
        impact_boost = min(high_impact_count * 0.03, 0.1)  # Max +0.1 from impact

        # Quality bonus - high quality similar findings boost confidence
        avg_quality = sum(f.quality_score for f in similar_findings) / len(similar_findings)
        quality_boost = min((avg_quality - 2) * 0.02, 0.05) if avg_quality > 2 else 0

        return count_boost + impact_boost + quality_boost

    def _generate_context_summary(
        self,
        hypothesis: dict,
        similar_findings: list[SoloditFinding],
        checklist_matches: list[dict],
    ) -> str:
        """Generate a human-readable context summary."""
        parts = []

        if similar_findings:
            parts.append(
                f"Found {len(similar_findings)} similar vulnerabilities in Solodit database."
            )
            # Mention top 3
            top_findings = similar_findings[:3]
            for f in top_findings:
                parts.append(f"  - [{f.impact}] {f.title} ({f.firm_name or 'Unknown firm'})")

        if checklist_matches:
            parts.append(
                f"\nMatches {len(checklist_matches)} Solodit checklist items:"
            )
            for item in checklist_matches[:3]:
                q = item.get("question", "")[:80]
                parts.append(f"  - {q}...")

        if not parts:
            parts.append("No similar findings or checklist matches found in Solodit.")

        return "\n".join(parts)

    async def enrich_hypothesis(
        self,
        hypothesis: dict,
        max_similar: int = 10,
    ) -> EnrichmentResult:
        """Enrich a single hypothesis with Solodit data.

        Args:
            hypothesis: Hypothesis dict with title, description, vulnerability_type
            max_similar: Maximum similar findings to retrieve

        Returns:
            EnrichmentResult with context and adjustments
        """
        hypothesis_id = hypothesis.get("id", "unknown")

        # Try tag-based search first (more accurate)
        tags = self._extract_tags(hypothesis)
        similar_findings = []

        if tags:
            for tag in tags[:2]:  # Limit to first 2 tags
                findings, _ = await self.client.search_findings(
                    tags=[tag],
                    impact=["HIGH", "MEDIUM"],
                    page_size=max_similar,
                )
                similar_findings.extend(findings)
        else:
            # Fall back to keyword search
            keywords = self._extract_keywords(hypothesis)
            for keyword in keywords[:2]:  # Limit to first 2 keywords
                findings, _ = await self.client.search_findings(
                    keywords=keyword,
                    impact=["HIGH", "MEDIUM"],
                    page_size=max_similar,
                )
                similar_findings.extend(findings)

        # Deduplicate by slug
        seen_slugs = set()
        unique_findings = []
        for f in similar_findings:
            if f.slug not in seen_slugs:
                seen_slugs.add(f.slug)
                unique_findings.append(f)

        similar_findings = unique_findings[:max_similar]

        # Cache findings
        for f in similar_findings:
            self.cache.cache_finding(f)

        # Match against checklist
        checklist_matches = []
        vuln_type = hypothesis.get("vulnerability_type", "")
        if vuln_type:
            checklist_matches = self.cache.get_checklist_category(vuln_type)

        # Calculate confidence adjustment
        confidence_adj = self._calculate_confidence_adjustment(
            hypothesis, similar_findings
        )

        # Generate summary
        summary = self._generate_context_summary(
            hypothesis, similar_findings, checklist_matches
        )

        return EnrichmentResult(
            hypothesis_id=hypothesis_id,
            similar_findings=similar_findings,
            checklist_matches=checklist_matches,
            confidence_adjustment=confidence_adj,
            context_summary=summary,
        )

    async def enrich_hypotheses(
        self,
        hypotheses: list[dict],
        max_similar: int = 5,
    ) -> list[EnrichmentResult]:
        """Enrich multiple hypotheses.

        Args:
            hypotheses: List of hypothesis dicts
            max_similar: Max similar findings per hypothesis

        Returns:
            List of EnrichmentResults
        """
        # Process sequentially to respect rate limits
        results = []
        for h in hypotheses:
            result = await self.enrich_hypothesis(h, max_similar)
            results.append(result)
        return results

    def enrich_hypothesis_sync(
        self,
        hypothesis: dict,
        max_similar: int = 10,
    ) -> EnrichmentResult:
        """Synchronous version of enrich_hypothesis."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(
            self.enrich_hypothesis(hypothesis, max_similar)
        )

    async def get_category_intelligence(
        self,
        category: str,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Get pre-audit intelligence for a protocol category.

        Args:
            category: Protocol category (DeFi, Lending, DEX, etc.)
            limit: Maximum findings to retrieve

        Returns:
            Dict with findings, common patterns, and checklist items
        """
        # Get relevant findings by protocol category
        findings, metadata = await self.client.search_findings(
            protocol_category=[category],
            impact=["HIGH", "MEDIUM"],
            sort_field="Quality",
            sort_direction="Desc",
            page_size=min(limit, 100),
        )

        # Cache them
        for f in findings:
            self.cache.cache_finding(f)

        # Get checklist items
        checklist_items = self.cache.get_checklist_category(category)

        # Analyze impact distribution
        impact_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "GAS": 0}
        for f in findings:
            if f.impact in impact_counts:
                impact_counts[f.impact] += 1

        return {
            "category": category,
            "findings_count": len(findings),
            "total_available": metadata.get("totalResults", len(findings)),
            "severity_distribution": impact_counts,  # Keep key name for compatibility
            "top_findings": [
                {
                    "title": f.title,
                    "impact": f.impact,
                    "severity": f.severity,  # For compatibility
                    "url": f.url,
                    "firm": f.firm_name,
                    "quality": f.quality_score,
                }
                for f in findings[:10]
            ],
            "checklist_items": len(checklist_items),
            "checklist_sample": checklist_items[:5],
        }
