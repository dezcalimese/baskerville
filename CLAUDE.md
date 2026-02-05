# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Baskerville** is an extended security analysis platform built on top of **Hound**, an AI-powered autonomous security analysis system. The platform uses dynamic knowledge graphs and strategic multi-agent collaboration to identify vulnerabilities in smart contracts.

### Architecture: Two CLIs

| CLI | Purpose | Commands |
|-----|---------|----------|
| `./hound.py` | Core analysis engine | `project`, `graph`, `agent`, `poc`, `finalize`, `report`, `static` |
| `./baskerville.py` | Full platform with extensions | All of hound + `solodit`, `kb`, `bounty` |

**Baskerville extensions:**
- **Solodit** - Cyfrin's vulnerability database (49k+ findings)
- **Knowledge Base** - Checklists, PoC templates, auditor tips
- **Bounty Workflow** - Contest scraping, platform formatters, submission prep

## Commands

### Installation
```bash
pip install -r requirements.txt
pip install -e ".[dev]"  # Include development tools
```

### Running Tests
```bash
pytest tests/ -v --tb=short                    # All tests
pytest tests/test_agent_core.py -v             # Single test file
pytest -m "not slow"                           # Skip slow tests
pytest -m integration                          # Integration tests only
pytest tests/ --cov=hound --cov-report=html    # With coverage
```

### Linting & Formatting
```bash
ruff check .                     # Lint (120 char line length)
black --line-length=100 .        # Format
mypy --strict .                  # Type check (Python 3.10)
```

### CLI Usage

**Hound Core (analysis engine):**
```bash
./hound.py project create <name> /path/to/code    # Create project
./hound.py graph build <name> --auto --files "src/A.sol,src/B.sol"
./hound.py agent audit <name> --mode sweep        # Breadth-first audit
./hound.py agent audit <name> --mode intuition    # Deep, targeted search
./hound.py finalize <name>                        # Quality review
./hound.py report <name>                          # Generate report
```

**Baskerville Extensions:**
```bash
# Bounty workflow
./baskerville.py bounty discover --save           # Find active contests
./baskerville.py bounty list --active             # List tracked contests
./baskerville.py bounty link <contest> <project>  # Link to Hound project
./baskerville.py bounty import <contest>          # Import findings
./baskerville.py bounty review <contest>          # Human review workflow
./baskerville.py bounty export <contest>          # Export for submission

# Knowledge base
./baskerville.py kb search "reentrancy"           # Search checklists/tips
./baskerville.py kb checklist --category oracle   # View checklist items
./baskerville.py kb template reentrancy           # Get PoC template

# Solodit integration
./baskerville.py solodit search "flash loan"      # Search vuln database
./baskerville.py solodit intel lending            # Pre-audit intelligence
./baskerville.py solodit enrich <project>         # Enrich hypotheses
```

## Architecture

### Core Design: Senior/Junior Model Pair
- **Scout model** (lightweight): Fast exploration and observation
- **Strategist model** (heavyweight): Planning, hypothesis formation, deep reasoning
- **Graph model** (large context): Knowledge graph construction
- **Lightweight model**: Utilities like deduplication

### Key Components

**`analysis/agent_core.py`** - `AutonomousAgent` class (~2600 lines)
- Main agent with autonomous decision-making
- Manages GraphStore and HypothesisStore
- Methods: `load_graph()`, `load_nodes()`, `update_node()`, `form_hypothesis()`, `update_hypothesis()`

**`analysis/strategist.py`** - Planning and reasoning
- Methods: `compose_plan()`, `hypothesize()`, `review_hypotheses()`
- Supports OpenAI reasoning_effort parameter (low/medium/high)

**`analysis/graph_builder.py`** - Knowledge graph construction (~1900 lines)
- Data structures: `DynamicNode`, `DynamicEdge`, `KnowledgeGraph`
- Iteratively builds nodes/edges from code with confidence scores

**`analysis/concurrent_knowledge.py`** - Thread-safe storage
- `GraphStore`, `HypothesisStore`, `CardStore`
- Port-based file locking via portalocker (cross-process safe)

**`llm/unified_client.py`** - Multi-provider LLM abstraction
- Supports: OpenAI, Anthropic, Google Gemini, X.AI (Grok), DeepSeek
- Automatic provider routing, fallback profiles, token tracking

### Directory Structure
```
baskerville/
├── hound.py           # Core CLI (analysis engine)
├── baskerville.py     # Extended CLI (wraps hound + extensions)
├── llm/               # Multi-provider LLM integration
├── analysis/          # Core agent, strategist, graph builder
├── commands/          # CLI command handlers
│   ├── project.py     # Hound core
│   ├── graph.py       # Hound core
│   ├── agent.py       # Hound core
│   ├── solodit.py     # Baskerville extension
│   ├── knowledge.py   # Baskerville extension
│   └── bounty.py      # Baskerville extension
├── extensions/        # Baskerville extension modules
│   ├── solodit/       # Solodit API client
│   ├── knowledge/     # Checklists, templates, tips
│   └── bounty/        # Contest workflow
├── ingest/            # Repository ingestion and bundling
├── utils/             # Config loader, JSON utilities
├── visualization/     # Graph visualization
├── chatbot/           # Web UI for steering audits
└── tests/             # Test suite
```

### Data Persistence

**Hound data** in `~/.hound/projects/<name>/`:
- `graphs/` - Knowledge graphs and card store
- `hypotheses.json` - Vulnerability findings
- `sessions/` - Per-session coverage, investigations, token usage
- `pocs/` - Proof-of-concept exploits

**Baskerville data** in `~/.hound/bounty/`:
- `contests/` - Contest state and metadata
- `findings/` - Findings per contest
- `exports/` - Formatted submissions

## Configuration

Config priority: explicit path > `HOUND_CONFIG` env > `config.yaml` in cwd > `config.yaml` in hound dir > `config.yaml.example`

Required API keys (environment variables):
- `OPENAI_API_KEY` (required)
- `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `XAI_API_KEY` (optional)
- `SOLODIT_API_KEY` (optional, for Solodit integration)
- For Vertex AI: `GOOGLE_USE_VERTEX_AI=1`, `VERTEX_PROJECT_ID`, `VERTEX_LOCATION`

## Testing Notes

- Uses pytest with pytest-asyncio for async tests
- Test markers: `@pytest.mark.slow`, `@pytest.mark.integration`
- `tests/conftest.py` handles import aliasing to avoid conflicts with global `llm` package
- Mock providers available for deterministic testing without API calls

## Import Handling

The codebase uses special path injection in `hound.py`, `baskerville.py`, and `tests/conftest.py` to avoid conflicts with a global `llm` package. The local `llm/` module is force-mapped to `hound.llm` in sys.modules.

## Development Practices

### Project Documentation
For every significant project or feature, write a detailed `FOR_<name>.md` file that explains the whole thing in plain language. This should include:
- Technical architecture and how the parts connect
- Technologies used and why we made these decisions
- Lessons learned: bugs we hit and how we fixed them, pitfalls to avoid
- New patterns or techniques worth remembering

Make it engaging to read - use analogies and anecdotes, not dry textbook prose.

### Bug Fixing Protocol
When a bug is reported, don't jump straight to fixing it. Instead:
1. **First**, write a test that reproduces the bug
2. **Then**, fix the bug and prove it with the passing test

This ensures we understand the bug, prevents regressions, and builds up the test suite.

## Extension Development

### Bounty Workflow State Machines

**Contest states:** `DISCOVERED` → `SCOPED` → `AUDITING` → `REVIEW` → `EXPORTED` → `SUBMITTED` → `ARCHIVED`

**Finding states:** `DETECTED` → `TRIAGED` → `ACCEPTED`/`REJECTED` → `REFINED` → `EXPORTED`

Human review gate: Findings are never auto-submitted. The `bounty export` command formats for platforms, but users must manually submit.

### Adding New Platform Formatters

Create a new formatter in `extensions/bounty/formatters/`:
```python
from .base import BaseFormatter, FormattedFinding

class NewPlatformFormatter(BaseFormatter):
    platform = "newplatform"

    def format_finding(self, finding: Finding) -> FormattedFinding:
        # Platform-specific markdown format
        ...
```

Register in `extensions/bounty/formatters/__init__.py`.
