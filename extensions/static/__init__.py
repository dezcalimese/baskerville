"""
Static analysis pipeline for smart contracts.

Integrates multiple static analyzers across EVM, Solana, and Sui/Aptos chains
to provide static vulnerability detection that feeds into Hound's hypothesis system.

Supported tools:
- EVM: Slither (Trail of Bits), Aderyn (Cyfrin)
- Solana: Soteria, cargo-audit
- Sui/Aptos: Move Prover, Sui Move Lint
"""

from .pipeline import StaticAnalysisPipeline
from .slither_runner import SlitherRunner
from .aderyn_runner import AderynRunner
from .soteria_runner import SoteriaRunner
from .cargo_audit_runner import CargoAuditRunner
from .move_prover_runner import MoveProverRunner
from .sui_move_lint_runner import SuiMoveLintRunner

__all__ = [
    "StaticAnalysisPipeline",
    "SlitherRunner",
    "AderynRunner",
    "SoteriaRunner",
    "CargoAuditRunner",
    "MoveProverRunner",
    "SuiMoveLintRunner",
]
