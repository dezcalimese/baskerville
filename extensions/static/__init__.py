"""
Static analysis pipeline for Solidity smart contracts.

Integrates Slither (Trail of Bits) and Aderyn (Cyfrin) to provide
static vulnerability detection that feeds into Hound's hypothesis system.
"""

from .pipeline import StaticAnalysisPipeline
from .slither_runner import SlitherRunner
from .aderyn_runner import AderynRunner

__all__ = ["StaticAnalysisPipeline", "SlitherRunner", "AderynRunner"]
