#!/usr/bin/env python3
"""Baskerville - Extended security analysis platform.

Wraps Hound core with additional capabilities:
- Solodit vulnerability database integration
- Security knowledge base
- Bounty workflow for audit contests
"""

import sys
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

import typer
from rich.console import Console

# Setup path for local imports (same as hound.py)
_BASE_DIR = Path(__file__).resolve().parent
_LLM_DIR = _BASE_DIR / "llm"
_BASE_DIR_STR = str(_BASE_DIR)
if sys.path[0] != _BASE_DIR_STR:
    try:
        sys.path.remove(_BASE_DIR_STR)
    except ValueError:
        pass
    sys.path.insert(0, _BASE_DIR_STR)

try:
    import types
    if 'llm' not in sys.modules:
        m = types.ModuleType('llm')
        m.__path__ = [str(_LLM_DIR)]
        sys.modules['llm'] = m
except Exception:
    pass

# Import Hound core
from hound import app as hound_app, _invoke_click

console = Console()

# Create Baskerville app that wraps Hound
app = typer.Typer(
    name="baskerville",
    help="Extended security analysis platform (wraps Hound core)",
    add_completion=False,
)

# Mount all Hound commands at root level
# Copy registered commands from hound_app
for cmd_info in hound_app.registered_commands:
    app.registered_commands.append(cmd_info)

# Copy registered command groups (project, agent, graph, etc.)
for group_info in hound_app.registered_groups:
    app.registered_groups.append(group_info)

# ─────────────────────────────────────────────────────────────────────────────
# Extension Command Groups
# ─────────────────────────────────────────────────────────────────────────────

solodit_app = typer.Typer(help="Solodit vulnerability database integration")
app.add_typer(solodit_app, name="solodit")

kb_app = typer.Typer(help="Knowledge base for security auditing")
app.add_typer(kb_app, name="kb")

bounty_app = typer.Typer(help="Bounty workflow for audit contests")
app.add_typer(bounty_app, name="bounty")


# ─────────────────────────────────────────────────────────────────────────────
# Solodit Commands
# ─────────────────────────────────────────────────────────────────────────────

@solodit_app.command("search")
def solodit_search(
    query: str = typer.Argument(..., help="Search keywords"),
    impact: str = typer.Option(None, "--impact", "-i", help="Filter by impact (HIGH, MEDIUM, LOW, GAS)"),
    tag: list[str] = typer.Option(None, "--tag", "-t", help="Filter by tag (can specify multiple)"),
    firm: list[str] = typer.Option(None, "--firm", "-f", help="Filter by audit firm (can specify multiple)"),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum results"),
    page: int = typer.Option(1, "--page", "-p", help="Page number"),
    sort: str = typer.Option("Recency", "--sort", "-s", help="Sort by (Recency, Quality, Rarity)")
):
    """Search Solodit vulnerability database."""
    from commands.solodit import search
    _invoke_click(search, {
        'query': query,
        'impact': impact,
        'tag': tuple(tag) if tag else (),
        'firm': tuple(firm) if firm else (),
        'limit': limit,
        'page': page,
        'sort': sort
    })


@solodit_app.command("checklist")
def solodit_checklist(
    category: str = typer.Option(None, "--category", "-c", help="Filter by category (e.g., reentrancy, access-control)"),
    refresh: bool = typer.Option(False, "--refresh", help="Force refresh from GitHub")
):
    """View Solodit security checklist."""
    from commands.solodit import checklist
    _invoke_click(checklist, {
        'category': category,
        'refresh': refresh
    })


@solodit_app.command("enrich")
def solodit_enrich(
    project_name: str = typer.Argument(..., help="Project name"),
    limit: int = typer.Option(5, "--limit", "-l", help="Max similar findings per hypothesis")
):
    """Enrich project hypotheses with Solodit context."""
    from commands.solodit import enrich
    _invoke_click(enrich, {
        'project_name': project_name,
        'limit': limit
    })


@solodit_app.command("intel")
def solodit_intel(
    category: str = typer.Argument(..., help="Protocol category (lending, amm, vault, governance, etc.)"),
    limit: int = typer.Option(20, "--limit", "-l", help="Max findings to retrieve")
):
    """Get pre-audit intelligence for a protocol category."""
    from commands.solodit import intel
    _invoke_click(intel, {
        'category': category,
        'limit': limit
    })


# ─────────────────────────────────────────────────────────────────────────────
# Knowledge Base Commands
# ─────────────────────────────────────────────────────────────────────────────

@kb_app.command("search")
def kb_search(
    query: str = typer.Argument(..., help="Search query"),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum results per category")
):
    """Search the knowledge base."""
    from commands.knowledge import search
    _invoke_click(search, {'query': query, 'limit': limit})


@kb_app.command("checklist")
def kb_checklist(
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    source: str = typer.Option("all", "--source", "-s", help="Filter by source (all, solodit, custom)"),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum results")
):
    """View security checklists."""
    from commands.knowledge import checklist
    _invoke_click(checklist, {'category': category, 'source': source, 'limit': limit})


@kb_app.command("categories")
def kb_categories():
    """List all checklist categories."""
    from commands.knowledge import categories
    _invoke_click(categories, {})


@kb_app.command("tips")
def kb_tips(
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    priority: str = typer.Option(None, "--priority", "-p", help="Filter by priority (high, medium, low)")
):
    """View auditor tips and heuristics."""
    from commands.knowledge import tips
    _invoke_click(tips, {'category': category, 'priority': priority})


@kb_app.command("template")
def kb_template(
    vuln_type: str = typer.Argument(..., help="Vulnerability type"),
    list_only: bool = typer.Option(False, "--list", "-l", help="List available templates")
):
    """Get PoC template for a vulnerability type."""
    from commands.knowledge import template
    _invoke_click(template, {'vuln_type': vuln_type, 'list_only': list_only})


@kb_app.command("stats")
def kb_stats():
    """Show knowledge base statistics."""
    from commands.knowledge import stats
    _invoke_click(stats, {})


@kb_app.command("context")
def kb_context(
    topic: str = typer.Argument(..., help="Topic to get context for"),
    protocol: bool = typer.Option(False, "--protocol", "-p", help="Treat topic as protocol type")
):
    """Get audit context for a topic (for LLM prompts)."""
    from commands.knowledge import context
    _invoke_click(context, {'topic': topic, 'protocol': protocol})


# ─────────────────────────────────────────────────────────────────────────────
# Bounty Workflow Commands
# ─────────────────────────────────────────────────────────────────────────────

@bounty_app.command("discover")
def bounty_discover(
    platform: str = typer.Option(None, "--platform", "-p", help="Specific platform to scrape"),
    save: bool = typer.Option(False, "--save", "-s", help="Save discovered contests")
):
    """Discover active contests from platforms."""
    from commands.bounty import discover
    _invoke_click(discover, {'platform': platform, 'save': save})


@bounty_app.command("list")
def bounty_list(
    active: bool = typer.Option(False, "--active", "-a", help="Show only active contests"),
    platform: str = typer.Option(None, "--platform", "-p", help="Filter by platform"),
    state: str = typer.Option(None, "--state", "-s", help="Filter by state")
):
    """List tracked contests."""
    from commands.bounty import list_contests
    _invoke_click(list_contests, {'active': active, 'platform': platform, 'state': state})


@bounty_app.command("show")
def bounty_show(
    contest_id: str = typer.Argument(..., help="Contest ID")
):
    """Show contest details."""
    from commands.bounty import show
    _invoke_click(show, {'contest_id': contest_id})


@bounty_app.command("add")
def bounty_add(
    url: str = typer.Argument(..., help="Contest URL"),
    platform: str = typer.Option(None, "--platform", "-p", help="Platform (auto-detected if not specified)"),
    name: str = typer.Option(None, "--name", "-n", help="Contest name")
):
    """Add a contest manually."""
    from commands.bounty import add
    _invoke_click(add, {'url': url, 'platform': platform, 'name': name})


@bounty_app.command("link")
def bounty_link(
    contest_id: str = typer.Argument(..., help="Contest ID"),
    project_name: str = typer.Argument(..., help="Hound project name")
):
    """Link contest to a Hound project."""
    from commands.bounty import link
    _invoke_click(link, {'contest_id': contest_id, 'project_name': project_name})


@bounty_app.command("import")
def bounty_import(
    contest_id: str = typer.Argument(..., help="Contest ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Re-import all findings")
):
    """Import findings from linked Hound project."""
    from commands.bounty import import_findings
    _invoke_click(import_findings, {'contest_id': contest_id, 'force': force})


@bounty_app.command("review")
def bounty_review(
    contest_id: str = typer.Argument(..., help="Contest ID"),
    severity: str = typer.Option(None, "--severity", "-s", help="Filter by severity")
):
    """Interactive review workflow for findings."""
    from commands.bounty import review
    _invoke_click(review, {'contest_id': contest_id, 'severity': severity})


@bounty_app.command("export")
def bounty_export(
    contest_id: str = typer.Argument(..., help="Contest ID"),
    output: str = typer.Option(None, "--output", "-o", help="Output directory"),
    fmt: str = typer.Option("individual", "--format", "-f", help="Export format (individual, report, both)")
):
    """Export findings for platform submission."""
    from commands.bounty import export
    _invoke_click(export, {'contest_id': contest_id, 'output': output, 'fmt': fmt})


@bounty_app.command("submit")
def bounty_submit(
    contest_id: str = typer.Argument(..., help="Contest ID"),
    notes: str = typer.Option(None, "--notes", "-n", help="Submission notes")
):
    """Mark contest as submitted (manual confirmation)."""
    from commands.bounty import submit
    _invoke_click(submit, {'contest_id': contest_id, 'notes': notes})


@bounty_app.command("stats")
def bounty_stats():
    """Show bounty statistics."""
    from commands.bounty import stats
    _invoke_click(stats, {})


@bounty_app.command("archive")
def bounty_archive(
    contest_id: str = typer.Argument(..., help="Contest ID")
):
    """Archive a contest."""
    from commands.bounty import archive
    _invoke_click(archive, {'contest_id': contest_id})


# ─────────────────────────────────────────────────────────────────────────────
# Baskerville-specific Commands
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def version():
    """Show Baskerville version."""
    console.print("[bold]Baskerville[/bold] v1.0.0")
    console.print("Extended security analysis platform")
    console.print("[dim]Built on Hound v2.0.0[/dim]")


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
