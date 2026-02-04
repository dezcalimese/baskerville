"""
Platform-specific formatters for contest submissions.

Each platform has different markdown/formatting requirements.
Formatters convert internal Finding objects to platform-specific format.
"""

from .base import BaseFormatter, FormattedFinding
from .code4rena import Code4renaFormatter
from .sherlock import SherlockFormatter
from .codehawks import CodeHawksFormatter
from .immunefi import ImmunefiFormatter


# Registry of platform formatters
FORMATTERS = {
    "code4rena": Code4renaFormatter,
    "sherlock": SherlockFormatter,
    "codehawks": CodeHawksFormatter,
    "immunefi": ImmunefiFormatter,
}


def get_formatter(platform: str) -> BaseFormatter:
    """Get formatter for a platform."""
    if platform not in FORMATTERS:
        raise ValueError(f"Unknown platform: {platform}. Available: {list(FORMATTERS.keys())}")
    return FORMATTERS[platform]()


__all__ = [
    "BaseFormatter",
    "FormattedFinding",
    "Code4renaFormatter",
    "SherlockFormatter",
    "CodeHawksFormatter",
    "ImmunefiFormatter",
    "get_formatter",
    "FORMATTERS",
]
