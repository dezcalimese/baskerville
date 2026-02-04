"""
Knowledge base for smart contract security auditing.

Provides structured access to:
- Security checklists (380+ items organized by category)
- PoC templates for common vulnerability classes
- Auditor tips and heuristics
- Semantic search via vector embeddings
"""

from .manager import KnowledgeBase
from .checklist_loader import ChecklistLoader
from .template_loader import TemplateLoader
from .tip_loader import TipLoader

__all__ = [
    "KnowledgeBase",
    "ChecklistLoader",
    "TemplateLoader",
    "TipLoader",
]
