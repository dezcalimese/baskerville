<p align="center">
  <img src="static/baskerville.png" alt="Baskerville Banner" width="75%">
</p>
<h1 align="center">Baskerville</h1>

<p align="center"><strong>Solidity-focused smart contract security auditing agent</strong></p>

<p align="center">
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/></a>
  <a href="https://anthropic.com"><img src="https://img.shields.io/badge/Anthropic-Compatible-6B46C1" alt="Anthropic"/></a>
  <a href="https://openai.com"><img src="https://img.shields.io/badge/OpenAI-Compatible-74aa9c" alt="OpenAI"/></a>
  <a href="https://ai.google.dev/"><img src="https://img.shields.io/badge/Gemini-Compatible-4285F4" alt="Gemini"/></a>
</p>

<p align="center">
  <sub>
    <a href="#overview"><b>Overview</b></a>
    • <a href="#what-baskerville-adds"><b>What Baskerville Adds</b></a>
    • <a href="#hound-core"><b>Hound Core</b></a>
    • <a href="#complete-audit-workflow"><b>Workflow</b></a>
  </sub>
</p>

---

## Overview

Baskerville is a smart contract security auditing agent built on top of [**Hound**](https://github.com/scabench-org/hound), Bernhard Mueller's open-source AI auditor. While Hound provides a powerful language-agnostic foundation for autonomous code auditing, Baskerville extends it with Solidity-specific tooling, vulnerability databases, and an automated bug bounty workflow.

The name references Baskerville from Hellsing — Alucard's familiar.

### What Hound Provides (the foundation)

Baskerville inherits all of Hound's core capabilities:

- **Knowledge graph builder** — Flexible, agent-designed graphs that model architecture, access control, value flows, math, etc.
- **Belief & hypothesis system** — Observations, assumptions, and hypotheses with confidence scores that evolve over time
- **Scout/Strategist model switching** — Lightweight models explore, heavyweight models reason deeply
- **Two audit modes** — `sweep` (systematic broad coverage) and `intuition` (targeted deep investigation)
- **Session management** — Resume sessions, track coverage, avoid duplicate work
- **PoC prompt generation** — Generates prompts for coding agents to write exploit PoCs
- **Report generation** — Professional HTML audit reports
- **Chatbot/Telemetry UI** — Web UI for live monitoring and steering audits

> **Links:** [Hound Paper](https://arxiv.org/html/2510.09633v1) • [Hound Walkthrough](https://muellerberndt.medium.com/hunting-for-security-bugs-in-code-with-ai-agents-a-full-walkthrough-a0dc24e1adf0)

## What Baskerville Adds

### Two CLIs: Core vs Extended

Baskerville provides two entry points:

| CLI | Purpose |
|-----|---------|
| `./hound.py` | Core analysis engine (project, graph, agent, poc, report) |
| `./baskerville.py` | Full platform with all extensions |

Use `./baskerville.py` for the complete workflow. Use `./hound.py` if you only need core analysis.

### Solodit Integration
Integration with Cyfrin's [Solodit](https://solodit.xyz) database of 49,000+ smart contract audit findings. Query past vulnerabilities reactively (when patterns are detected) or proactively (before auditing a protocol category).

```bash
./baskerville.py solodit search "flash loan attack"   # Search findings
./baskerville.py solodit intel lending                # Pre-audit intelligence
./baskerville.py solodit enrich myproject             # Enrich hypotheses
```

### Static Analysis Pipeline
Orchestrated pipeline running Slither, Aderyn, and custom AST patterns *before* the LLM touches code. Results feed into Hound's hypothesis system as initial observations.

### Audit Knowledge Base
Structured checklists (380+ items from Solodit + custom), Foundry PoC templates by vulnerability class, and auditor heuristics.

```bash
./baskerville.py kb search "reentrancy"               # Search all knowledge
./baskerville.py kb checklist --category oracle       # View checklist items
./baskerville.py kb template reentrancy               # Get PoC template
./baskerville.py kb tips --priority high              # View auditor tips
```

### Bounty/Contest Workflow
Automated workflow for Code4rena, Sherlock, CodeHawks, and Immunefi contests — contest scraping, platform-specific formatters, and submission preparation with a human review gate (never auto-submits).

```bash
./baskerville.py bounty discover --save               # Find active contests
./baskerville.py bounty list --active                 # List tracked contests
./baskerville.py bounty link <contest> <project>      # Link to Hound project
./baskerville.py bounty import <contest>              # Import findings
./baskerville.py bounty review <contest>              # Human review workflow
./baskerville.py bounty export <contest>              # Export for submission
```

**State Machine:** Contests flow through `DISCOVERED` → `SCOPED` → `AUDITING` → `REVIEW` → `EXPORTED` → `SUBMITTED`

**Human Review Gate:** Findings are never auto-submitted. Export formats for the platform, but you submit manually.

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Set up your API keys:

```bash
# Required for LLM analysis
export OPENAI_API_KEY=your_key_here
export ANTHROPIC_API_KEY=your_key_here  # recommended for Claude models

# Optional: Solodit API for vulnerability database
export SOLODIT_API_KEY=your_key_here    # Get from Cyfrin
```

Using Gemini via Vertex AI (optional):

```bash
export GOOGLE_USE_VERTEX_AI=1
export VERTEX_PROJECT_ID=my-gcp-project
export VERTEX_LOCATION=us-central1
# Then: gcloud auth application-default login
```

Copy and edit the config:

```bash
cp config.yaml.example config.yaml
```

**Note:** Audit quality scales with time and model capability. Use longer runs and advanced models for more complete results.

---

## Hound Core

The sections below document Hound's core functionality, which Baskerville builds on top of.

## Complete Audit Workflow

### Step 1: Create a Project

Projects organize your audits and store all analysis data:

```bash
# Create a project from local code
./hound.py project create myaudit /path/to/code

# List all projects
./hound.py project ls

# View project details and coverage
./hound.py project info myaudit
```

### Step 2: Build Knowledge Graphs

Hound analyzes your codebase and builds aspect‑oriented knowledge graphs that serve as the foundation for all subsequent analysis.

Recommended (one‑liner):

```bash
# Auto-generate a default set of graphs (up to 5) and refine
# Strongly recommended: pass a whitelist of files (comma-separated)
./hound.py graph build myaudit --auto \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# View generated graphs
./hound.py graph ls myaudit
```

Alternative (manual guidance):

```bash
# 1) Initialize the baseline SystemArchitecture graph
./hound.py graph build myaudit --init \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# 2) Add a specific graph with your own description (exactly one graph)
./hound.py graph custom myaudit \
  "Call graph focusing on function call relationships across modules" \
  --iterations 2 \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# (Repeat 'graph custom' for additional targeted graphs as needed)
```

Operational notes:
- `--auto` always includes the SystemArchitecture graph as the first graph. You do not need to run `--init` in addition to `--auto`.
- If `--init` is used and a `SystemArchitecture` graph already exists, initialization is skipped. Use `--auto` to add more graphs, or remove existing graphs first if you want a clean re‑init.
- When running `--auto` and graphs already exist, Hound asks for confirmation before updating/overwriting graphs (including SystemArchitecture). To clear graphs:

```bash
./hound.py graph rm myaudit --all                 # remove all graphs
./hound.py graph rm myaudit --name SystemArchitecture  # remove one graph
```

- For large repos, you can constrain scope with `--files` (comma‑separated whitelist) alongside either approach.

Whitelists (strongly recommended):

- Always pass a whitelist of input files via `--files`. For the best results, the selected files should fit in the model's available context window; whitelisting keeps the graph builder focused and avoids token overflows.
- If you do not pass `--files`, Hound will consider all files in the repository. On large codebases this triggers sampling and may degrade coverage/quality.
- `--files` expects a comma‑separated list of paths relative to the repo root.

Examples:

```bash
# Manual (small projects)
./hound.py graph build myaudit --auto \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# Use the generated list (newline-separated) as a comma list for --files
./hound.py graph build myaudit --auto \
  --files "$(tr '\n' ',' < whitelists/myaudit | sed 's/,$//')"
```

- Refine existing graphs (resume building):

You can resume/refine an existing graph without creating new ones using `graph refine`. This skips discovery and saves updates incrementally.

```bash
# Refine a single graph by name (internal or display)
./hound.py graph refine myaudit SystemArchitecture \
  --iterations 2 \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# Refine all existing graphs
./hound.py graph refine myaudit --all --iterations 2 \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"
```

### Step 3: Run the Audit

The audit phase uses the **senior/junior pattern** with planning and investigation:

```bash
# 1. Sweep all components for shallow bugs, build code understanding
./hound.py agent audit myaudit --mode sweep

# 2. Intuition-guided search to find complex bugs
./hound.py agent audit myaudit --mode intuition --time-limit 300

# Start with telemetry (connect the Chatbot UI to steer)
./hound.py agent audit myaudit --mode intuition --time-limit 30 --telemetry

# Attach to an existing session and continue where you left off
./hound.py agent audit myaudit --mode intuition --session <session_id>
```

Tip: When started with `--telemetry`, you can connect the Chatbot UI and steer the audit interactively (see Chatbot section above).

**Audit Modes:**

Hound supports two distinct audit modes:

- **Sweep Mode (`--mode sweep`)**: Phase 1 - Systematic component analysis
  - Performs a broad, systematic analysis of every major component
  - Examines each contract, module, and class for vulnerabilities
  - Builds comprehensive graph annotations for later analysis
  - Terminates when all accessible components have been analyzed
  - Best for: Initial vulnerability discovery and building code understanding

- **Intuition Mode (`--mode intuition`)**: Phase 2 - Deep, targeted exploration
  - Uses intuition-guided search to find high-impact vulnerabilities
  - Prioritizes monetary flows, value transfers, and theft opportunities
  - Investigates contradictions between assumptions and observations
  - Focuses on authentication bypasses and state corruption
  - Best for: Finding complex, cross-component vulnerabilities

**Key parameters:**
- **--time-limit**: Stop after N minutes (useful for incremental audits)
- **--plan-n**: Number of investigations per planning batch
- **--session**: Resume a specific session (continues coverage/planning)
- **--debug**: Save all LLM interactions to `.hound_debug/`

Normally, you want to run sweep mode first followed by intuition mode. The quality and duration depend heavily on the models used. Faster models provide quick results but may miss subtle issues, while advanced reasoning models find deeper vulnerabilities but require more time.

### Step 4: Monitor Progress

Check audit progress and findings at any time during the audit. If you started the agent with `--telemetry`, you can also monitor and steer via the Chatbot UI:

- Open http://127.0.0.1:5280 and attach to the running instance
- Watch live Activity, Plan, and Findings
- Use the Steer form to guide the next investigations

```bash
# View current hypotheses (findings)
./hound.py project ls-hypotheses myaudit

# See detailed hypothesis information
./hound.py project hypotheses myaudit --details

# List hypotheses with confidence ratings
./hound.py project hypotheses myaudit

# Check coverage statistics
./hound.py project coverage myaudit

# View session details
./hound.py project sessions myaudit --list
```

**Understanding hypotheses:** Each hypothesis represents a potential vulnerability with:
- **Confidence score**: 0.0-1.0 indicating likelihood of being a real issue
- **Status**: `proposed` (initial), `investigating`, `confirmed`, `rejected`
- **Severity**: critical, high, medium, low
- **Type**: reentrancy, access control, logic error, etc.
- **Annotations**: Exact code locations and evidence

### Step 5: Run Targeted Investigations (Optional)

For specific concerns, run focused investigations without full planning:

```bash
# Investigate a specific concern
./hound.py agent investigate "Check for reentrancy in withdraw function" myaudit

# Quick investigation with fewer iterations
./hound.py agent investigate "Analyze access control in admin functions" myaudit \
  --iterations 5

# Use specific models for investigation
./hound.py agent investigate "Review emergency functions" myaudit \
  --model gpt-4o \
  --strategist-model claude-opus-4
```

**When to use targeted investigations:**
- Following up on specific concerns after initial audit
- Testing a hypothesis about a particular vulnerability
- Quick checks before full audit
- Investigating areas not covered by automatic planning

**Note:** These investigations still update the hypothesis store and coverage tracking.

### Step 6: Quality Assurance

A reasoning model reviews all hypotheses and updates their status based on evidence:

```bash
# Run finalization with quality review
./hound.py finalize myaudit
# Re-run all pending (including below threshold)
./hound.py finalize myaudit --include-below-threshold

# Customize confidence threshold
./hound.py finalize myaudit -t 0.7 --model gpt-4o

# Include all findings (not just confirmed)
# (Use on the report command, not finalize)
./hound.py report myaudit --all
```

**What happens during finalization:**
1. A reasoning model reviews each hypothesis
2. Evaluates the evidence and code context
3. Updates status to `confirmed` or `rejected` based on analysis
4. Adjusts confidence scores based on evidence strength
5. Prepares findings for report generation

**Important:** By default, only `confirmed` findings appear in the final report. Use `--include-all` to include all hypotheses regardless of status.

### Step 7: Generate Proof-of-Concepts

Create and manage proof-of-concept exploits for confirmed vulnerabilities:

```bash
# Generate PoC prompts for confirmed vulnerabilities
./hound.py poc make-prompt myaudit

# Generate for a specific hypothesis
./hound.py poc make-prompt myaudit --hypothesis hyp_12345

# Import existing PoC files
./hound.py poc import myaudit hyp_12345 exploit.sol test.js \
  --description "Demonstrates reentrancy exploit"

# List all imported PoCs
./hound.py poc list myaudit
```

**The PoC workflow:**
1. **make-prompt**: Generates detailed prompts for coding agents (like Claude Code)
   - Includes vulnerable file paths (project-relative)
   - Specifies exact functions to target
   - Provides clear exploit requirements
   - Saves prompts to `poc_prompts/` directory

2. **import**: Links PoC files to specific vulnerabilities
   - Files stored in `poc/[hypothesis-id]/`
   - Metadata tracks descriptions and timestamps
   - Multiple files per vulnerability supported

3. **Automatic inclusion**: Imported PoCs appear in reports with syntax highlighting

### Step 8: Generate Professional Reports

Produce comprehensive audit reports with all findings and PoCs:

```bash
# Generate HTML report (includes imported PoCs)
./hound.py report myaudit

# Include all hypotheses, not just confirmed
./hound.py report myaudit --include-all

# Export report to specific location
./hound.py report myaudit --output /path/to/report.html
```

**Report contents:**
- **Executive summary**: High-level overview and risk assessment
- **System architecture**: Understanding of the codebase structure
- **Findings**: Detailed vulnerability descriptions (only `confirmed` by default)
- **Code snippets**: Relevant vulnerable code with line numbers
- **Proof-of-concepts**: Any imported PoCs with syntax highlighting
- **Severity distribution**: Visual breakdown of finding severities
- **Recommendations**: Suggested fixes and improvements

## Session Management

Each audit run operates under a session with comprehensive tracking and per-session planning:

- Planning is stored in a per-session PlanStore with statuses: `planned`, `in_progress`, `done`, `dropped`, `superseded`.
- Existing `planned` items are executed first; Strategist only tops up new items to reach your `--plan-n`.
- On resume, any stale `in_progress` items are reset to `planned`; completed items remain `done` and are not duplicated.
- Completed investigations, coverage, and hypotheses are fed back into planning to avoid repeats and guide prioritization.

```bash
# View session details
./hound.py project sessions myaudit <session_id>

# List and inspect sessions
./hound.py project sessions myaudit --list
./hound.py project sessions myaudit <session_id>

# Show planned investigations for a session (Strategist PlanStore)
./hound.py project plan myaudit <session_id>

# Session data includes:
# - Coverage statistics (nodes/cards visited)
# - Investigation history
# - Token usage by model
# - Planning decisions
# - Hypothesis formation
```

Sessions are stored in `~/.hound/projects/myaudit/sessions/` and contain:
- `session_id`: Unique identifier
- `coverage`: Visited nodes and analyzed code
- `investigations`: All executed investigations
- `planning_history`: Strategic decisions made
- `token_usage`: Detailed API usage metrics

Resume/attach to an existing session during an audit run by passing the session ID:

```bash
# Attach to a specific session and continue auditing under it
./hound.py agent audit myaudit --session <session_id>
```

When you attach to a session, its status is set to `active` while the audit runs and finalized on completion (`completed` or `interrupted` if a time limit was hit). Any `in_progress` plan items are reset to `planned` so you can continue cleanly.

### Simple Planning Examples

```bash
# Start an audit (creates a session automatically)
./hound.py agent audit myaudit

# List sessions to get the session id
./hound.py project sessions myaudit --list

# Show planned investigations for that session
./hound.py project plan myaudit <session_id>

# Attach later and continue planning/execution under the same session
./hound.py agent audit myaudit --session <session_id>
```

## Chatbot (Telemetry UI)

Hound ships with a lightweight web UI for steering and monitoring a running audit session. It discovers local runs via a simple telemetry registry and streams status/decisions live.

Prerequisites:
- Set API keys (at least `OPENAI_API_KEY`, optional `OPENAI_BASE_URL` for custom endpoints): `source ../API_KEYS.txt` or export manually
- Install Python deps in this submodule: `pip install -r requirements.txt`

1) Start the agent with telemetry enabled

```bash
# From the hound/ directory
./hound.py agent audit myaudit --telemetry --debug

# Notes
# - The --telemetry flag exposes a local SSE/control endpoint and registers the run
# - Optional: ensure the registry dir matches the chatbot by setting:
#   export HOUND_REGISTRY_DIR="$HOME/.local/state/hound/instances"
```

2) Launch the chatbot server

```bash
# From the hound/ directory
python chatbot/run.py

# Optional: customize host/port
HOST=0.0.0.0 PORT=5280 python chatbot/run.py
```

Open the UI: http://127.0.0.1:5280

3) Select the running instance and stream activity

- The input next to "Start" lists detected instances as `project_path | instance_id`.
- Click "Start" to attach; the UI auto‑connects the realtime channel and begins streaming decisions/results.
- The lower panel has tabs:
  - Activity: live status/decisions
  - Plan: current strategist plan (✓ done, ▶ active, • pending)
  - Findings: hypotheses with confidence; you can Confirm/Reject manually

4) Steer the audit

- Use the "Steer" form (e.g., "Investigate reentrancy across the whole app next").
- Steering is queued at `<project>/.hound/steering.jsonl` and consumed exactly once when applied.
- Broad, global instructions may preempt the current investigation and trigger immediate replanning.

Troubleshooting
- No instances in dropdown: ensure you started the agent with `--telemetry`.
- Wrong or stale project shown: clear the input; the UI defaults to the most recent alive instance.
- Registry mismatch: confirm both processes print the same `Using registry dir:` or set `HOUND_REGISTRY_DIR` for both.
- Raw API: open `/api/instances` in the browser to inspect entries (includes `alive` flag and registry path).

## Managing Hypotheses

Hypotheses are the core findings that accumulate across sessions:

```bash
# List hypotheses with confidence scores
./hound.py project hypotheses myaudit

# View with full details
./hound.py project hypotheses myaudit --details

# Update hypothesis status
./hound.py project set-hypothesis-status myaudit hyp_12345 confirmed

# Reset hypotheses (creates backup)
./hound.py project reset-hypotheses myaudit

# Force reset without confirmation
./hound.py project reset-hypotheses myaudit --force
```

Hypothesis statuses:
- **proposed**: Initial finding, needs review
- **investigating**: Under active investigation
- **confirmed**: Verified vulnerability
- **rejected**: False positive
- **resolved**: Fixed in code

## Advanced Features

### Model Selection

Override default models per component:

```bash
# Use different models for each role
./hound.py agent audit myaudit \
  --platform anthropic --model claude-haiku-4   # Scout
  --strategist-platform anthropic --strategist-model claude-opus-4   # Strategist
```

### Debug Mode

Capture all LLM interactions for analysis:

```bash
# Enable debug logging
./hound.py agent audit myaudit --debug

# Debug logs saved to .hound_debug/
# Includes HTML reports with all prompts and responses
```

### Coverage Tracking

Monitor audit progress and completeness:

```bash
# View coverage statistics
./hound.py project coverage myaudit

# Coverage shows:
# - Graph nodes visited vs total
# - Code cards analyzed vs total
# - Percentage completion
```

---

## License

Apache 2.0 — see [LICENSE.txt](LICENSE.txt)

## Acknowledgments

Baskerville is built on [Hound](https://github.com/scabench-org/hound) by Bernhard Mueller (creator of [Mythril](https://github.com/Consensys/mythril)).
