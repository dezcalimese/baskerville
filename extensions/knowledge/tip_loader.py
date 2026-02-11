"""
Auditor tips and heuristics loader.

Provides quick-access tips and patterns for common audit scenarios.
"""

import yaml
from pathlib import Path
from dataclasses import dataclass


@dataclass
class AuditorTip:
    """An auditor tip or heuristic."""
    id: str
    title: str
    category: str
    tip: str
    code_pattern: str | None  # Optional regex or code pattern to look for
    tags: list[str]
    priority: str  # high, medium, low
    chain: str = "evm"


class TipLoader:
    """Loads and queries auditor tips."""

    def __init__(self, tips_dir: Path | None = None):
        """Initialize loader."""
        if tips_dir is None:
            tips_dir = Path(__file__).parent / "tips"
        self.tips_dir = tips_dir
        self._tips: list[AuditorTip] = []
        self._loaded = False

    def _load(self) -> None:
        """Load all tips."""
        if self._loaded:
            return

        self._tips = self._get_builtin_tips()

        # Load from YAML files
        if self.tips_dir.exists():
            for yaml_file in self.tips_dir.glob("*.yaml"):
                try:
                    with open(yaml_file) as f:
                        data = yaml.safe_load(f)
                    if data and "tips" in data:
                        # Read top-level chain key as default for all tips in this file
                        file_chain = data.get("chain", "evm")
                        for tip_data in data["tips"]:
                            self._tips.append(AuditorTip(
                                id=tip_data.get("id", ""),
                                title=tip_data.get("title", ""),
                                category=tip_data.get("category", yaml_file.stem),
                                tip=tip_data.get("tip", ""),
                                code_pattern=tip_data.get("code_pattern"),
                                tags=tip_data.get("tags", []),
                                priority=tip_data.get("priority", "medium"),
                                chain=tip_data.get("chain", file_chain),
                            ))
                except Exception as e:
                    print(f"[!] Failed to load tips from {yaml_file}: {e}")

        self._loaded = True

    def _get_builtin_tips(self) -> list[AuditorTip]:
        """Get built-in auditor tips."""
        return [
            # Reentrancy
            AuditorTip(
                id="TIP-REEN-01",
                title="Look for external calls before state changes",
                category="Reentrancy",
                tip="Search for `.call{`, `.transfer(`, `.send(` and verify state changes happen BEFORE these calls.",
                code_pattern=r"\.(call|transfer|send)\s*[{(]",
                tags=["reentrancy", "CEI"],
                priority="high",
            ),
            AuditorTip(
                id="TIP-REEN-02",
                title="Check ERC721/1155 safe transfers",
                category="Reentrancy",
                tip="safeTransferFrom triggers callbacks. Look for _safeMint, safeTransferFrom without reentrancy guards.",
                code_pattern=r"(safeTransferFrom|_safeMint)",
                tags=["reentrancy", "ERC721", "ERC1155"],
                priority="high",
            ),

            # Access Control
            AuditorTip(
                id="TIP-AC-01",
                title="Find unprotected initialize functions",
                category="Access Control",
                tip="Search for `initialize` or `init` functions. Verify they have `initializer` modifier and can't be called twice.",
                code_pattern=r"function\s+init(ialize)?",
                tags=["access-control", "initializer", "proxy"],
                priority="high",
            ),
            AuditorTip(
                id="TIP-AC-02",
                title="Check for missing access control",
                category="Access Control",
                tip="Look for functions that modify state but lack `onlyOwner`, `onlyRole`, or similar modifiers.",
                code_pattern=None,
                tags=["access-control", "modifier"],
                priority="high",
            ),

            # Oracle
            AuditorTip(
                id="TIP-ORC-01",
                title="Check Chainlink staleness",
                category="Oracle",
                tip="If using latestRoundData(), ensure there's a check: `require(updatedAt > block.timestamp - MAX_DELAY)`",
                code_pattern=r"latestRoundData\(\)",
                tags=["oracle", "chainlink", "staleness"],
                priority="high",
            ),
            AuditorTip(
                id="TIP-ORC-02",
                title="Spot price manipulation",
                category="Oracle",
                tip="If price is derived from pool reserves or balances, it can be flash-manipulated. Look for getReserves(), balanceOf().",
                code_pattern=r"(getReserves|balanceOf).*price",
                tags=["oracle", "manipulation", "flash-loan"],
                priority="high",
            ),

            # Math
            AuditorTip(
                id="TIP-MATH-01",
                title="Division before multiplication",
                category="Math",
                tip="Look for patterns like `a / b * c`. This loses precision. Should be `a * c / b`.",
                code_pattern=r"/\s*\w+\s*\*",
                tags=["math", "precision"],
                priority="medium",
            ),
            AuditorTip(
                id="TIP-MATH-02",
                title="Unchecked arithmetic",
                category="Math",
                tip="Search for `unchecked {` blocks. Verify the math truly can't overflow/underflow.",
                code_pattern=r"unchecked\s*\{",
                tags=["math", "overflow", "unchecked"],
                priority="medium",
            ),

            # Tokens
            AuditorTip(
                id="TIP-TOKEN-01",
                title="Fee-on-transfer tokens",
                category="Tokens",
                tip="If protocol accepts arbitrary tokens, check for fee-on-transfer. Use balanceAfter - balanceBefore pattern.",
                code_pattern=r"transferFrom\(",
                tags=["token", "fee-on-transfer"],
                priority="high",
            ),
            AuditorTip(
                id="TIP-TOKEN-02",
                title="Token decimals assumption",
                category="Tokens",
                tip="Don't assume 18 decimals. USDC has 6, WBTC has 8. Check decimals() and normalize.",
                code_pattern=r"10\s*\*\*\s*18",
                tags=["token", "decimals"],
                priority="medium",
            ),

            # DeFi
            AuditorTip(
                id="TIP-DEFI-01",
                title="ERC4626 inflation attack",
                category="DeFi",
                tip="For vaults, check first depositor protection. Look for totalSupply() == 0 edge cases.",
                code_pattern=r"totalSupply\(\)\s*==\s*0",
                tags=["vault", "ERC4626", "inflation"],
                priority="high",
            ),
            AuditorTip(
                id="TIP-DEFI-02",
                title="Flash loan integration",
                category="DeFi",
                tip="Check if protocol uses or can be attacked via flash loans. Look for executeOperation, flashLoan callbacks.",
                code_pattern=r"(executeOperation|flashLoan|uniswapV3.*Callback)",
                tags=["flash-loan", "callback"],
                priority="high",
            ),

            # Gas/DoS
            AuditorTip(
                id="TIP-DOS-01",
                title="Unbounded loops",
                category="DoS",
                tip="Look for loops over arrays/mappings that grow unbounded. `for (uint i = 0; i < array.length; i++)`",
                code_pattern=r"for\s*\([^)]+\.length",
                tags=["dos", "gas", "loop"],
                priority="medium",
            ),
            AuditorTip(
                id="TIP-DOS-02",
                title="External call in loop",
                category="DoS",
                tip="External calls in loops can cause DoS if one call fails. Check for try/catch or pull patterns.",
                code_pattern=None,
                tags=["dos", "loop", "external-call"],
                priority="medium",
            ),
        ]

    def get_all(self) -> list[AuditorTip]:
        """Get all tips."""
        self._load()
        return self._tips

    def get_by_chain(self, chain_id: str) -> list[AuditorTip]:
        """Get tips filtered by chain.

        Args:
            chain_id: Chain identifier (e.g., "evm", "solana", "sui")

        Returns:
            List of tips matching the given chain
        """
        self._load()
        chain_lower = chain_id.lower()
        return [t for t in self._tips if t.chain.lower() == chain_lower]

    def get_by_category(self, category: str) -> list[AuditorTip]:
        """Get tips by category."""
        self._load()
        category_lower = category.lower()
        return [t for t in self._tips if category_lower in t.category.lower()]

    def get_by_priority(self, priority: str) -> list[AuditorTip]:
        """Get tips by priority."""
        self._load()
        return [t for t in self._tips if t.priority == priority]

    def search(self, query: str) -> list[AuditorTip]:
        """Search tips."""
        self._load()
        query_lower = query.lower()
        return [
            t for t in self._tips
            if query_lower in t.title.lower() or
               query_lower in t.tip.lower() or
               any(query_lower in tag.lower() for tag in t.tags)
        ]

    def get_patterns(self) -> list[tuple[str, str]]:
        """Get all code patterns with their tip IDs."""
        self._load()
        return [(t.id, t.code_pattern) for t in self._tips if t.code_pattern]
