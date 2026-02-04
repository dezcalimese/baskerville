"""
Bounty workflow for audit contests.

Handles the full lifecycle of participating in audit contests:
- Contest discovery and scope parsing
- Audit execution with Hound
- Human review workflow
- Platform-specific export formatting
- Submission tracking (never auto-submit)
"""

from .contest import Contest, ContestState, InvalidStateTransition
from .finding import Finding, FindingState, Severity, InvalidFindingTransition
from .scraper import ContestScraper, ScrapedContest
from .storage import BountyStorage
from .formatters import get_formatter, FORMATTERS

__all__ = [
    # Contest
    "Contest",
    "ContestState",
    "InvalidStateTransition",
    # Finding
    "Finding",
    "FindingState",
    "Severity",
    "InvalidFindingTransition",
    # Scraper
    "ContestScraper",
    "ScrapedContest",
    # Storage
    "BountyStorage",
    # Formatters
    "get_formatter",
    "FORMATTERS",
]
