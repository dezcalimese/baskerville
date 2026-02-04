"""
Solodit integration for vulnerability database access.

Provides access to Solodit's 49,000+ audit findings for:
- Cross-referencing Hound hypotheses against known vulnerabilities
- Pre-audit intelligence gathering by protocol category
- Enriching findings with historical context
"""

from .client import SoloditClient, SoloditFinding
from .cache import SoloditCache
from .enricher import HypothesisEnricher

__all__ = ["SoloditClient", "SoloditFinding", "SoloditCache", "HypothesisEnricher"]
