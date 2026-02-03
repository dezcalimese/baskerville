# Baskerville Roadmap

## Build Phases

### Phase 1: Hound Core Validation
Get Hound running as-is. Configure Claude as strategist. Test on a known vulnerable contract (e.g., Damn Vulnerable DeFi). Validate: ingest → graph → sweep → findings.

**Status:** 🚧 In Progress

**Completed:**
- ✅ Local model support via LM Studio (LocalModelProvider)
  - JSON extraction from markdown/thinking tags
  - JSON repair for malformed output
  - Auto-detection of localhost URLs
  - Tested with GLM 4.7 flash + Qwen 8B
- ✅ Configured for M4 Max 64GB (GLM flash for scout/strategist, Qwen 8B for lightweight)
- ✅ Tested on Damn Vulnerable DeFi (SideEntrance) - found reentrancy vulnerabilities

**Remaining:**
- [ ] Full end-to-end audit on larger contract
- [ ] Validate all audit modes (sweep + intuition)
- [ ] Test session resume/continuation
- [ ] Test report generation with findings

### Phase 2: Static Analysis Pipeline (`extensions/static/`)
Build the static analysis pipeline. Wire Slither and Aderyn output into Hound's hypothesis system.

- `pipeline.py` — Orchestrator that runs tools in sequence: Slither → Aderyn → custom AST patterns
- `slither_runner.py` — Wrapper for Slither (Trail of Bits), parses JSON output into structured findings
- `aderyn_runner.py` — Wrapper for Aderyn (Cyfrin's Rust-based Solidity analyzer)
- `ast_patterns.py` — Custom AST pattern matchers for Solidity-specific patterns the tools miss

Pipeline output feeds into Hound's hypothesis system as initial observations.

**Status:** Planned

### Phase 3: Solodit Integration (`extensions/solodit/`)
Build the Solodit integration. Start with the MCP server bridge (available now), add REST API client when beta access is granted.

- `client.py` — REST API client for Solodit's API (beta access, key via `SOLODIT_API_KEY` env var)
- `mcp_bridge.py` — Integration with the Solodit MCP server (npm package by Lyuboslav Lyubenov) as fallback when API is unavailable
- `cache.py` — Local SQLite cache with text embeddings for offline/fast access to frequently queried findings
- `enricher.py` — Takes Hound hypotheses and cross-references them against Solodit findings to validate, add context, and find similar past vulnerabilities

Two usage modes:
- **Reactive**: When the agent identifies a pattern (e.g., `delegatecall` in proxy), query Solodit for similar past findings
- **Proactive**: Before auditing a protocol category (lending, AMM, vault), pull all related high/critical findings as context

**Status:** Planned

### Phase 4: Knowledge Base (`extensions/knowledge/`)
Build the knowledge base. Structure checklists, create PoC templates, set up vector store.

- `checklists/` — Solodit's 380+ item checklist structured as queryable YAML/JSON, plus custom checklists per protocol category
- `templates/` — Foundry PoC templates by vulnerability class (reentrancy, oracle manipulation, flash loan, access control, logic errors, ERC compliance issues)
- `tips/` — Auditor heuristics and rules
- `embeddings/` — Vector store (ChromaDB) for semantic search over past audits, checklist items, and exploit patterns

**Status:** Planned

### Phase 5: Bounty Workflow (`extensions/bounty/`)
Build the bounty workflow. Contest scrapers, platform formatters, human review gate.

- `scraper.py` — Scrapes contest details (scope files, docs, known issues, timeline) from C4, Sherlock, CodeHawks, Immunefi
- `formatters/` — Platform-specific report formatters:
  - `code4rena.py` — C4 markdown submission format
  - `sherlock.py` — Sherlock submission format
  - `codehawks.py` — CodeHawks format
  - `immunefi.py` — Immunefi bug bounty format
- `submission.py` — Submission preparation with human review gate (never auto-submit)

**Status:** Planned

### Phase 6: CLI Wrapper (`baskerville.py`)
Build the CLI wrapper that ties everything together.

```
baskerville audit <path> --auto                    # Full audit pipeline
baskerville bounty start <contest_url>             # Start contest workflow
baskerville bounty review                          # Review findings before submit
baskerville bounty export --format c4              # Export in platform format
baskerville solodit search <query>                 # Search Solodit DB
baskerville solodit checklist --category lending   # Pull category checklist
baskerville investigate <description> <project>    # Targeted investigation
```

**Status:** Planned

---

## Solidity-Specific Graph Templates (`extensions/solidity/`)

To be built alongside other phases as needed:

- `erc_patterns.py` — Graph templates for ERC20, ERC721, ERC4626, ERC777 patterns and their known edge cases
- `defi_graphs.py` — Templates for lending protocols, AMMs, vaults, perpetuals, governance
- `proxy_analysis.py` — Proxy pattern detection (UUPS, Transparent, Beacon), storage layout analysis, upgrade safety

---

## Target Project Structure

```
baskerville/
├── hound/                    # Original Hound code (forked, minimally modified)
│
├── extensions/               # All Baskerville extensions
│   ├── solodit/
│   │   ├── client.py
│   │   ├── mcp_bridge.py
│   │   ├── cache.py
│   │   └── enricher.py
│   │
│   ├── static/
│   │   ├── pipeline.py
│   │   ├── slither_runner.py
│   │   ├── aderyn_runner.py
│   │   └── ast_patterns.py
│   │
│   ├── solidity/
│   │   ├── erc_patterns.py
│   │   ├── defi_graphs.py
│   │   └── proxy_analysis.py
│   │
│   ├── bounty/
│   │   ├── scraper.py
│   │   ├── formatters/
│   │   │   ├── code4rena.py
│   │   │   ├── sherlock.py
│   │   │   ├── codehawks.py
│   │   │   └── immunefi.py
│   │   └── submission.py
│   │
│   └── knowledge/
│       ├── checklists/
│       ├── templates/
│       ├── tips/
│       └── embeddings/
│
├── data/                     # Reference data
│   ├── past_audits/
│   ├── exploit_patterns/
│   └── protocol_docs/
│
├── config.yaml
├── baskerville.py            # Main CLI entry point (wraps hound.py)
└── requirements.txt
```

---

## Model Configuration

### Cloud Models (Recommended for production)
| Role | Model | Purpose |
|---|---|---|
| Scout | Claude Haiku 4 | Fast exploration, broad coverage |
| Strategist | Claude Opus 4 | Deep reasoning, hypothesis validation |
| PoC Generator | Claude Sonnet 4 | Code generation for exploit PoCs |
| Report Writer | Claude Sonnet 4 | Structured report output |

### Local Models (LM Studio - M4 Max 64GB)
| Role | Model | Purpose |
|---|---|---|
| Scout | zai-org/glm-4.7-flash | Fast exploration, good JSON output |
| Strategist | zai-org/glm-4.7-flash | Reasoning (or qwen3-coder-30b-a3b@4bit if RAM allows) |
| Lightweight | qwen/qwen3-8b | Fast dedup, simple tasks, 32K context |
| Graph | zai-org/glm-4.7-flash | Graph building, 128K context |

**Local model setup:**
```bash
# .env
OPENAI_API_KEY=lm-studio
OPENAI_BASE_URL=http://localhost:1234/v1
```

---

## Key Principles

- **Extend, don't rewrite** — Hound's core (graphs, hypotheses, sessions, coverage) is battle-tested. Build on top of it.
- **Human in the loop** — Never auto-submit to bounty platforms. Always require human review.
- **Cache aggressively** — Solodit queries, static analysis results, embeddings. Avoid redundant API calls.
- **Track everything** — Acceptance rates on platforms become the feedback signal for tuning.
- **Solidity-first** — While Hound is language-agnostic, Baskerville optimizes specifically for Solidity/EVM smart contracts.
