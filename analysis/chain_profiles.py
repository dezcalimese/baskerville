"""
Chain profile system for multi-chain security analysis.

Encapsulates all chain-specific knowledge (terminology, vulnerability patterns,
prompt supplements, static tools) so the rest of the codebase stays chain-agnostic.
"""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ChainProfile:
    """All chain-specific knowledge needed for analysis."""

    chain_id: str                       # "evm", "solana", "sui", "aptos"
    display_name: str                   # "Solana/Anchor", "Sui/Move"
    languages: list[str]                # ["rust"], ["move"]
    file_extensions: list[str]          # [".rs"], [".move"]
    module_term: str                    # "contract" / "program" / "module"
    module_term_plural: str             # "contracts" / "programs" / "modules"
    function_term: str                  # "function" / "instruction handler" / "entry function"
    access_control_patterns: list[str]  # chain-specific examples
    state_term: str                     # "storage" / "account data" / "shared objects"
    vulnerability_categories: list[str] # top 15 for this chain
    graph_type_suggestions: list[str]   # chain-appropriate graph types
    code_language: str                  # for markdown code blocks
    static_tools: list[str]            # available static analyzers
    project_root_markers: list[str]    # ["Anchor.toml"], ["Move.toml"]
    agent_prompt_supplement: str        # appended to agent system prompt
    strategist_prompt_supplement: str   # appended to strategist prompts
    graph_builder_supplement: str       # graph type suggestions

    # Short annotation examples for the scout prompt
    annotation_examples: list[str] = field(default_factory=list)


def evm_profile() -> ChainProfile:
    """EVM/Solidity chain profile (default)."""
    return ChainProfile(
        chain_id="evm",
        display_name="EVM/Solidity",
        languages=["solidity", "vyper"],
        file_extensions=[".sol", ".vy"],
        module_term="contract",
        module_term_plural="contracts",
        function_term="function",
        access_control_patterns=[
            "onlyOwner", "onlyRole(Role)", "require(msg.sender == owner)",
            "initializer", "nonReentrant", "whenNotPaused",
        ],
        state_term="storage",
        vulnerability_categories=[
            "reentrancy", "access control bypass", "oracle manipulation",
            "flash loan attack", "integer overflow/underflow", "front-running/MEV",
            "denial of service", "price manipulation", "storage collision",
            "uninitialized proxy", "signature replay", "ERC4626 inflation",
            "unchecked return values", "delegatecall injection", "griefing",
        ],
        graph_type_suggestions=[
            "AuthorizationMap: who grants/assumes/authorizes which roles/actions (edges: creates, grants, assumes, authorizes, guarded_by)",
            "PermissionChecks: coverage of access modifiers and require checks per function (edges: guarded_by, unchecked, requires_role)",
            "AssetFlow: mint/burn/transfer/deposit/withdraw across contracts and accounts (edges: mints, burns, transfers, deposits, withdraws)",
            "StateMutation: storage variables and the functions that read/write them (edges: written_by, read_by, derived_from)",
            "UpgradeLifecycle: deployment/initialization/upgrade relationships (edges: deploys, initializes, upgrades, migrates_from)",
            "ExternalDeps: external/oracle/library dependencies and trust boundaries (edges: reads_from, depends_on, trusts, verifies)",
            "Reentrancy/ExternalCalls: external call graph with entrypoints and reentrant paths (edges: calls_external, reentrant_path, invokes_untrusted)",
            "InvariantsMap: key invariants/assumptions and where they're enforced (edges: enforced_by, broken_by, relies_on)",
            "MathAlgorithm: break down core formulas/AMM math into steps/variables (edges: computes, uses_param, normalizes, clamps)",
            "EventMap: which events are emitted by which functions and with what state (edges: emitted_by, indexes, correlates_with)",
            "TimeWindows/RateLimits: time-based gates and limits (edges: gates, bounded_by, cooldown)",
        ],
        code_language="solidity",
        static_tools=["slither", "aderyn"],
        project_root_markers=["foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js"],
        annotation_examples=[
            "only owner", "checks balance", "emits Transfer", "nonReentrant",
            "unchecked", "token transfer", "external call", "pausable",
        ],
        agent_prompt_supplement="",
        strategist_prompt_supplement="",
        graph_builder_supplement="",
    )


def solana_profile() -> ChainProfile:
    """Solana/Anchor chain profile."""
    return ChainProfile(
        chain_id="solana",
        display_name="Solana/Anchor",
        languages=["rust"],
        file_extensions=[".rs"],
        module_term="program",
        module_term_plural="programs",
        function_term="instruction handler",
        access_control_patterns=[
            "has_one = authority", "#[account(signer)]", "require_keys_eq!",
            "constraint = ctx.accounts.authority.key() == expected",
            "Signer<'info>", "#[access_control]",
        ],
        state_term="account data",
        vulnerability_categories=[
            "missing signer check", "missing owner check",
            "account type confusion (discriminator)", "PDA seed collision / bump manipulation",
            "CPI privilege escalation", "arbitrary CPI target",
            "integer overflow (release mode wraps)", "reinitialization",
            "closing account vulnerabilities (data zeroing, revival)",
            "missing rent exemption check", "lamport accounting mismatch",
            "sysvar spoofing", "token account validation (mint/owner/authority)",
            "missing freeze authority check", "unsafe deserialization / remaining bytes",
        ],
        graph_type_suggestions=[
            "AccountValidation: which accounts are validated and how (edges: validates, requires_signer, requires_owner, checks_discriminator, unchecked)",
            "CPIGraph: cross-program invocations and privilege flow (edges: invokes, passes_signer, escalates_to, trusts)",
            "SignerAuthority: signer requirements per instruction (edges: requires_signer, delegates_to, authority_of, unchecked_signer)",
            "AccountOwnership: program ownership and account derivation (edges: owns, derives_pda, seeds_from, associated_with)",
            "LamportFlow: SOL and token balance flows (edges: transfers_sol, transfers_token, mints, burns, closes_to)",
            "StateMutation: account data fields and instruction handlers that read/write them (edges: written_by, read_by, initialized_by, closed_by)",
            "PDASeedMap: PDA derivation seeds and potential collisions (edges: derived_from, seeds, bump_source, collides_with)",
            "InvariantsMap: critical invariants and where they're enforced (edges: enforced_by, broken_by, relies_on)",
        ],
        code_language="rust",
        static_tools=["soteria", "cargo-audit"],
        project_root_markers=["Anchor.toml", "Cargo.toml"],
        annotation_examples=[
            "has_one authority", "signer check", "CPI call", "PDA derived",
            "unchecked account", "close account", "lamport transfer", "init",
        ],
        agent_prompt_supplement=(
            "\n\nSOLANA-SPECIFIC ANALYSIS GUIDANCE:\n"
            "- Account validation is the #1 attack surface. For every instruction, check:\n"
            "  * Is the signer verified? (Signer<'info> or has_one constraint)\n"
            "  * Is the account owner checked? (Account<'info, T> with correct program owner)\n"
            "  * Is the account discriminator checked? (Anchor auto-checks, but manual deserialization may not)\n"
            "- CPI (Cross-Program Invocation) is the Solana equivalent of external calls:\n"
            "  * Check if signer seeds are properly validated before CPI\n"
            "  * Look for arbitrary program ID in CPI targets\n"
            "- PDA (Program Derived Address) security:\n"
            "  * Check for seed collisions across different account types\n"
            "  * Verify bump seeds are stored/validated correctly\n"
            "- Solana integers wrap in release mode (no overflow panic). Look for unchecked math.\n"
            "- Account closing: data must be zeroed AND lamports drained to prevent revival.\n"
        ),
        strategist_prompt_supplement=(
            "\n\nSOLANA VULNERABILITY PRIORITIES:\n"
            "1. Missing signer/owner checks on state-mutating instructions\n"
            "2. CPI privilege escalation and arbitrary CPI targets\n"
            "3. PDA seed collisions enabling account confusion\n"
            "4. Integer overflow in release builds (wrapping arithmetic)\n"
            "5. Account closing bugs (data not zeroed, lamports not fully drained)\n"
            "6. Token account validation (wrong mint, wrong authority)\n"
            "7. Reinitialization of already-initialized accounts\n"
        ),
        graph_builder_supplement=(
            "Ideas for strong, analysis-friendly graphs for Solana programs:\n"
            "- AccountValidation: which accounts are validated and how (edges: validates, requires_signer, requires_owner, checks_discriminator, unchecked)\n"
            "- CPIGraph: cross-program invocations and privilege flow (edges: invokes, passes_signer, escalates_to, trusts)\n"
            "- SignerAuthority: signer requirements per instruction (edges: requires_signer, delegates_to, authority_of, unchecked_signer)\n"
            "- AccountOwnership: program ownership and account derivation (edges: owns, derives_pda, seeds_from, associated_with)\n"
            "- LamportFlow: SOL and token balance flows (edges: transfers_sol, transfers_token, mints, burns, closes_to)\n"
            "- StateMutation: account data fields and instruction handlers that read/write them (edges: written_by, read_by, initialized_by, closed_by)\n"
            "- PDASeedMap: PDA derivation seeds and potential collisions (edges: derived_from, seeds, bump_source, collides_with)\n"
            "- InvariantsMap: critical invariants and where they're enforced (edges: enforced_by, broken_by, relies_on)\n"
        ),
    )


def sui_profile() -> ChainProfile:
    """Sui/Move chain profile."""
    return ChainProfile(
        chain_id="sui",
        display_name="Sui/Move",
        languages=["move"],
        file_extensions=[".move"],
        module_term="module",
        module_term_plural="modules",
        function_term="entry function",
        access_control_patterns=[
            "public(friend)", "entry fun", "TxContext",
            "assert!(tx_context::sender(ctx) == owner)", "Capability pattern",
            "witness pattern (one-time witness)", "transfer::freeze_object",
        ],
        state_term="shared objects",
        vulnerability_categories=[
            "shared object race conditions", "capability leakage",
            "one-time witness misuse", "type confusion via generics",
            "dynamic field manipulation", "object ownership transfer exploits",
            "flash loan / hot potato pattern misuse",
            "missing public(friend) restrictions", "arithmetic overflow via `as` casts",
            "unchecked public_transfer on shared objects", "package upgrade attacks",
            "clock manipulation", "event reliance for state",
            "missing assert! in entry functions", "frozen object bypass",
        ],
        graph_type_suggestions=[
            "ObjectOwnership: object ownership model and transfer patterns (edges: owns, transfers, shares, freezes, wraps, unwraps)",
            "CapabilityFlow: capability creation, delegation, and consumption (edges: creates_cap, delegates, consumes, guards)",
            "DynamicFieldGraph: dynamic field additions and access patterns (edges: adds_field, removes_field, borrows_field, mutates_field)",
            "WitnessPatternMap: one-time witness usage and type authority (edges: creates_witness, consumes_witness, authorizes_type)",
            "SharedObjectAccess: shared object access patterns and potential races (edges: borrows_mut, borrows_immut, races_with, ordered_by)",
            "ModuleVisibility: function visibility and friend relationships (edges: calls, friend_of, public_entry, restricted_to)",
            "AssetFlow: coin/token creation, splitting, merging, and transfer (edges: mints, burns, splits, merges, transfers)",
            "InvariantsMap: critical invariants and where they're enforced (edges: enforced_by, broken_by, relies_on)",
        ],
        code_language="move",
        static_tools=["sui-move-prove", "sui-move-lint"],
        project_root_markers=["Move.toml"],
        annotation_examples=[
            "shared object", "capability guard", "one-time witness", "entry fun",
            "public(friend)", "dynamic field", "hot potato", "frozen",
        ],
        agent_prompt_supplement=(
            "\n\nSUI/MOVE-SPECIFIC ANALYSIS GUIDANCE:\n"
            "- Object ownership model is the core security primitive:\n"
            "  * Owned objects: only owner can use in transactions\n"
            "  * Shared objects: anyone can access, prone to race conditions\n"
            "  * Frozen objects: immutable, but check for bypass via wrapping\n"
            "- Capability pattern: capabilities grant authority. Check for:\n"
            "  * Capability leakage (stored in accessible locations)\n"
            "  * Missing capability checks on sensitive operations\n"
            "- One-time witness (OTW): used for type authority. Verify:\n"
            "  * OTW is consumed (not stored or copied)\n"
            "  * OTW struct has correct properties (drop, no fields)\n"
            "- Type confusion via generics: Move generics are powerful but can be abused\n"
            "  * Check that generic type parameters are properly constrained\n"
            "  * Look for phantom type parameter misuse\n"
            "- Dynamic fields: check for unauthorized field manipulation\n"
            "- Hot potato pattern: objects that must be consumed in same transaction\n"
        ),
        strategist_prompt_supplement=(
            "\n\nSUI/MOVE VULNERABILITY PRIORITIES:\n"
            "1. Shared object race conditions (concurrent access exploits)\n"
            "2. Capability leakage or missing capability checks\n"
            "3. One-time witness not properly consumed or validated\n"
            "4. Type confusion through unconstrained generics\n"
            "5. Dynamic field manipulation (unauthorized add/remove)\n"
            "6. Object ownership transfer exploits\n"
            "7. Missing public(friend) restrictions on sensitive functions\n"
        ),
        graph_builder_supplement=(
            "Ideas for strong, analysis-friendly graphs for Sui/Move modules:\n"
            "- ObjectOwnership: object ownership model and transfer patterns (edges: owns, transfers, shares, freezes, wraps, unwraps)\n"
            "- CapabilityFlow: capability creation, delegation, and consumption (edges: creates_cap, delegates, consumes, guards)\n"
            "- DynamicFieldGraph: dynamic field additions and access patterns (edges: adds_field, removes_field, borrows_field, mutates_field)\n"
            "- WitnessPatternMap: one-time witness usage and type authority (edges: creates_witness, consumes_witness, authorizes_type)\n"
            "- SharedObjectAccess: shared object access patterns and potential races (edges: borrows_mut, borrows_immut, races_with, ordered_by)\n"
            "- ModuleVisibility: function visibility and friend relationships (edges: calls, friend_of, public_entry, restricted_to)\n"
            "- AssetFlow: coin/token creation, splitting, merging, and transfer (edges: mints, burns, splits, merges, transfers)\n"
            "- InvariantsMap: critical invariants and where they're enforced (edges: enforced_by, broken_by, relies_on)\n"
        ),
    )


def aptos_profile() -> ChainProfile:
    """Aptos/Move chain profile."""
    return ChainProfile(
        chain_id="aptos",
        display_name="Aptos/Move",
        languages=["move"],
        file_extensions=[".move"],
        module_term="module",
        module_term_plural="modules",
        function_term="entry function",
        access_control_patterns=[
            "public entry fun", "acquires", "signer::address_of",
            "assert!(signer::address_of(account) == @admin)",
            "friend module", "capability pattern",
        ],
        state_term="global storage resources",
        vulnerability_categories=[
            "resource duplication via generic abuse", "capability leakage",
            "missing signer validation", "type confusion via generics",
            "table manipulation exploits", "coin registration bypass",
            "flash loan pattern misuse", "missing friend restrictions",
            "arithmetic overflow via casts", "unchecked resource movement",
            "module upgrade attacks", "timestamp manipulation",
            "event ordering dependence", "missing acquires annotation",
            "global storage exhaustion",
        ],
        graph_type_suggestions=[
            "ResourceFlow: resource creation, movement, and destruction (edges: creates, moves_to, moves_from, destroys, borrows)",
            "CapabilityFlow: capability creation, delegation, and consumption (edges: creates_cap, delegates, consumes, guards)",
            "SignerAuthority: signer requirements per entry function (edges: requires_signer, validates_address, unchecked_signer)",
            "ModuleVisibility: function visibility and friend relationships (edges: calls, friend_of, public_entry, restricted_to)",
            "TableAccess: table operations and access patterns (edges: creates_table, adds_entry, removes_entry, borrows_entry)",
            "CoinFlow: coin registration, minting, and transfer (edges: registers, mints, burns, transfers, withdraws, deposits)",
            "AcquiresGraph: resource acquires dependencies (edges: acquires, borrows_global, moves_global)",
            "InvariantsMap: critical invariants and where they're enforced (edges: enforced_by, broken_by, relies_on)",
        ],
        code_language="move",
        static_tools=["move-prover", "aptos-move-lint"],
        project_root_markers=["Move.toml"],
        annotation_examples=[
            "acquires Resource", "signer check", "friend module", "entry fun",
            "table operation", "coin transfer", "capability guard", "borrow_global",
        ],
        agent_prompt_supplement=(
            "\n\nAPTOS/MOVE-SPECIFIC ANALYSIS GUIDANCE:\n"
            "- Aptos Move uses a resource-oriented model with global storage:\n"
            "  * Resources live at addresses, accessed via borrow_global/move_to/move_from\n"
            "  * `acquires` annotation is required and affects composability\n"
            "- Signer validation is critical:\n"
            "  * Check signer::address_of() is used to validate the signer\n"
            "  * Entry functions receive &signer but must verify it's the expected account\n"
            "- Type safety with generics:\n"
            "  * Move's type system is strong but generics can enable confusion\n"
            "  * Check for phantom type parameters and generic resource abuse\n"
            "- Table operations: Aptos tables are similar to mappings\n"
            "  * Check for missing existence checks before borrow\n"
            "  * Look for table key collision issues\n"
            "- Coin framework: check registration, minting authority, and transfer patterns\n"
        ),
        strategist_prompt_supplement=(
            "\n\nAPTOS/MOVE VULNERABILITY PRIORITIES:\n"
            "1. Missing signer validation on entry functions\n"
            "2. Resource duplication or destruction bugs\n"
            "3. Capability leakage or missing capability checks\n"
            "4. Type confusion through unconstrained generics\n"
            "5. Table manipulation (missing existence checks, key collisions)\n"
            "6. Coin registration and minting authority bypass\n"
            "7. Missing friend restrictions on sensitive functions\n"
        ),
        graph_builder_supplement=(
            "Ideas for strong, analysis-friendly graphs for Aptos/Move modules:\n"
            "- ResourceFlow: resource creation, movement, and destruction (edges: creates, moves_to, moves_from, destroys, borrows)\n"
            "- CapabilityFlow: capability creation, delegation, and consumption (edges: creates_cap, delegates, consumes, guards)\n"
            "- SignerAuthority: signer requirements per entry function (edges: requires_signer, validates_address, unchecked_signer)\n"
            "- ModuleVisibility: function visibility and friend relationships (edges: calls, friend_of, public_entry, restricted_to)\n"
            "- TableAccess: table operations and access patterns (edges: creates_table, adds_entry, removes_entry, borrows_entry)\n"
            "- CoinFlow: coin registration, minting, and transfer (edges: registers, mints, burns, transfers, withdraws, deposits)\n"
            "- AcquiresGraph: resource acquires dependencies (edges: acquires, borrows_global, moves_global)\n"
            "- InvariantsMap: critical invariants and where they're enforced (edges: enforced_by, broken_by, relies_on)\n"
        ),
    )


# Registry of all profiles
CHAIN_PROFILES: dict[str, callable] = {
    "evm": evm_profile,
    "solana": solana_profile,
    "sui": sui_profile,
    "aptos": aptos_profile,
}


def get_profile(chain_id: str) -> ChainProfile:
    """Get a chain profile by ID.

    Args:
        chain_id: Chain identifier ("evm", "solana", "sui", "aptos")

    Returns:
        ChainProfile for the chain

    Raises:
        ValueError: If chain_id is not recognized
    """
    factory = CHAIN_PROFILES.get(chain_id)
    if factory is None:
        valid = ", ".join(CHAIN_PROFILES.keys())
        raise ValueError(f"Unknown chain '{chain_id}'. Valid chains: {valid}")
    return factory()


def detect_chain_from_files(source_path: str | Path) -> str:
    """Auto-detect chain from project files.

    Detection order:
    1. Project root markers (Anchor.toml, Move.toml, foundry.toml, etc.)
    2. File extension majority

    Args:
        source_path: Path to project source code

    Returns:
        Chain ID string ("evm", "solana", "sui", "aptos")
    """
    source_path = Path(source_path)
    if not source_path.exists():
        return "evm"  # Default

    # Phase 1: Check for project root markers
    # Anchor.toml is definitive for Solana
    if (source_path / "Anchor.toml").exists():
        return "solana"

    # Move.toml could be Sui or Aptos - check for sui-specific content
    move_toml = source_path / "Move.toml"
    if move_toml.exists():
        try:
            content = move_toml.read_text()
            # Sui projects reference the Sui framework
            if "sui" in content.lower() or "SuiFramework" in content or "0x2" in content:
                return "sui"
            # Aptos projects reference the Aptos framework
            if "aptos" in content.lower() or "AptosFramework" in content or "0x1" in content:
                return "aptos"
            # Default Move.toml to Sui (more common for new projects)
            return "sui"
        except Exception:
            return "sui"

    # Check for EVM markers
    for marker in ["foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js", "brownie-config.yaml"]:
        if (source_path / marker).exists():
            return "evm"

    # Cargo.toml with anchor dependency -> Solana
    cargo_toml = source_path / "Cargo.toml"
    if cargo_toml.exists():
        try:
            content = cargo_toml.read_text()
            if "anchor" in content.lower() or "solana" in content.lower():
                return "solana"
        except Exception:
            pass

    # Phase 2: File extension majority
    ext_counts: dict[str, int] = {}
    ext_to_chain = {
        ".sol": "evm",
        ".vy": "evm",
        ".move": "sui",  # Default Move to Sui
        ".rs": "solana",  # Rust in non-Anchor project still likely Solana
    }

    try:
        for ext, chain in ext_to_chain.items():
            count = len(list(source_path.rglob(f"*{ext}")))
            if count > 0:
                ext_counts[chain] = ext_counts.get(chain, 0) + count
    except Exception:
        pass

    if ext_counts:
        return max(ext_counts, key=ext_counts.get)

    return "evm"  # Default
