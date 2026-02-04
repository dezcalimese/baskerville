"""
Knowledge base CLI commands.

Usage:
    ./hound.py kb search <query>           # Search all knowledge
    ./hound.py kb checklist [--category]   # View checklists
    ./hound.py kb tips [--category]        # View auditor tips
    ./hound.py kb template <vuln-type>     # Get PoC template
    ./hound.py kb stats                    # Show statistics
"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

sys.path.insert(0, str(Path(__file__).parent.parent))

from extensions.knowledge import KnowledgeBase, ChecklistLoader, TemplateLoader, TipLoader


console = Console()


@click.group("kb")
def kb():
    """Knowledge base for security auditing."""
    pass


@kb.command("search")
@click.argument("query")
@click.option("--limit", "-l", default=20, help="Maximum results per category")
def search(query: str, limit: int):
    """Search the knowledge base."""
    console.print(f"\n[bold]Searching knowledge base for: {query}[/bold]\n")

    kb = KnowledgeBase()
    result = kb.query(query)

    # Checklists
    if result.checklists:
        console.print(f"[bold cyan]Checklist Items ({len(result.checklists)})[/bold cyan]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("ID", width=15)
        table.add_column("Question", width=50)
        table.add_column("Source", width=8)

        for item in result.checklists[:limit]:
            table.add_row(
                item.id,
                item.question[:50] + ("..." if len(item.question) > 50 else ""),
                item.source,
            )
        console.print(table)
        console.print()

    # Tips
    if result.tips:
        console.print(f"[bold cyan]Auditor Tips ({len(result.tips)})[/bold cyan]")
        for tip in result.tips[:limit]:
            console.print(f"  [{tip.priority.upper()}] [bold]{tip.title}[/bold]")
            console.print(f"          {tip.tip[:80]}...")
        console.print()

    # Templates
    if result.templates:
        console.print(f"[bold cyan]PoC Templates ({len(result.templates)})[/bold cyan]")
        for template in result.templates[:limit]:
            console.print(f"  • [bold]{template.name}[/bold]: {template.description}")
        console.print()

    if not result.checklists and not result.tips and not result.templates:
        console.print("[yellow]No results found.[/yellow]")


@kb.command("checklist")
@click.option("--category", "-c", help="Filter by category")
@click.option("--source", "-s", type=click.Choice(["all", "solodit", "custom"]), default="all", help="Filter by source")
@click.option("--limit", "-l", default=20, help="Maximum results")
def checklist(category: str | None, source: str, limit: int):
    """View security checklists."""
    console.print("\n[bold]Security Checklists[/bold]\n")

    loader = ChecklistLoader()

    if category:
        items = loader.get_by_category(category)
        console.print(f"[dim]Showing items for category: {category}[/dim]\n")
    else:
        items = loader.get_all()

    # Filter by source
    if source == "solodit":
        items = [i for i in items if i.source == "solodit"]
    elif source == "custom":
        items = [i for i in items if i.source == "custom"]

    if not items:
        console.print("[yellow]No checklist items found.[/yellow]")

        # Show available categories
        categories = loader.get_categories()
        if categories:
            console.print(f"\n[dim]Available categories: {', '.join(categories[:10])}...[/dim]")
        return

    console.print(f"Found {len(items)} items (showing {min(len(items), limit)})\n")

    for item in items[:limit]:
        severity_color = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
        }.get(item.severity, "white")

        console.print(f"[{severity_color}][{item.id}][/{severity_color}] {item.question}")
        if item.description:
            console.print(f"    [dim]{item.description[:100]}...[/dim]")
        console.print()

    # Show stats
    stats = loader.stats()
    console.print(f"[dim]Total: {stats['total']} items ({stats['solodit']} from Solodit, {stats['custom']} custom)[/dim]")


@kb.command("categories")
def categories():
    """List all checklist categories."""
    console.print("\n[bold]Checklist Categories[/bold]\n")

    loader = ChecklistLoader()
    cats = loader.get_categories()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Category", width=40)
    table.add_column("Items", width=10)

    for cat in sorted(cats):
        items = loader.get_by_category(cat)
        # Only exact matches for count
        exact_items = [i for i in items if i.category == cat]
        table.add_row(cat, str(len(exact_items)))

    console.print(table)
    console.print(f"\n[dim]Total: {len(cats)} categories[/dim]")


@kb.command("tips")
@click.option("--category", "-c", help="Filter by category")
@click.option("--priority", "-p", type=click.Choice(["high", "medium", "low"]), help="Filter by priority")
def tips(category: str | None, priority: str | None):
    """View auditor tips and heuristics."""
    console.print("\n[bold]Auditor Tips & Heuristics[/bold]\n")

    loader = TipLoader()
    all_tips = loader.get_all()

    if category:
        all_tips = loader.get_by_category(category)
    if priority:
        all_tips = [t for t in all_tips if t.priority == priority]

    if not all_tips:
        console.print("[yellow]No tips found.[/yellow]")
        return

    # Group by category
    by_category: dict[str, list] = {}
    for tip in all_tips:
        if tip.category not in by_category:
            by_category[tip.category] = []
        by_category[tip.category].append(tip)

    for cat, cat_tips in sorted(by_category.items()):
        console.print(f"[bold cyan]{cat}[/bold cyan]")
        for tip in cat_tips:
            priority_color = {"high": "red", "medium": "yellow", "low": "blue"}.get(tip.priority, "white")
            console.print(f"  [{priority_color}]●[/{priority_color}] [bold]{tip.title}[/bold]")
            console.print(f"    {tip.tip}")
            if tip.code_pattern:
                console.print(f"    [dim]Pattern: {tip.code_pattern}[/dim]")
            console.print()


@kb.command("template")
@click.argument("vuln_type")
@click.option("--list", "-l", "list_only", is_flag=True, help="List available templates")
def template(vuln_type: str, list_only: bool):
    """Get PoC template for a vulnerability type."""
    loader = TemplateLoader()

    if list_only:
        console.print("\n[bold]Available PoC Templates[/bold]\n")
        for t in loader.list_all():
            console.print(f"  [bold]{t.id}[/bold] - {t.name}")
            console.print(f"    {t.description}")
            console.print(f"    [dim]Tags: {', '.join(t.tags)}[/dim]")
            console.print()
        return

    templates = loader.get_by_vulnerability(vuln_type)

    if not templates:
        console.print(f"[yellow]No template found for: {vuln_type}[/yellow]")
        console.print("\n[dim]Available templates:[/dim]")
        for t in loader.list_all():
            console.print(f"  • {t.id}: {t.name}")
        return

    template = templates[0]
    console.print(f"\n[bold]PoC Template: {template.name}[/bold]")
    console.print(f"[dim]{template.description}[/dim]\n")

    if template.placeholders:
        console.print("[bold]Placeholders to fill:[/bold]")
        for ph in template.placeholders:
            console.print(f"  • {{{{{ph}}}}}")
        console.print()

    # Show template code
    syntax = Syntax(template.template, "solidity", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=f"{template.id}.sol", border_style="dim"))


@kb.command("stats")
def stats():
    """Show knowledge base statistics."""
    console.print("\n[bold]Knowledge Base Statistics[/bold]\n")

    kb = KnowledgeBase()
    stats = kb.stats()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Component", width=20)
    table.add_column("Count", width=15)
    table.add_column("Details", width=30)

    # Checklists
    cl_stats = stats["checklists"]
    table.add_row(
        "Checklists",
        str(cl_stats["total"]),
        f"{cl_stats['solodit']} Solodit + {cl_stats['custom']} custom",
    )
    table.add_row(
        "Categories",
        str(cl_stats["categories"]),
        "",
    )

    # Templates
    table.add_row(
        "PoC Templates",
        str(stats["templates"]),
        "",
    )

    # Tips
    table.add_row(
        "Auditor Tips",
        str(stats["tips"]),
        "",
    )

    console.print(table)


@kb.command("context")
@click.argument("topic")
@click.option("--protocol", "-p", is_flag=True, help="Treat topic as protocol type (lending, amm, etc.)")
def context(topic: str, protocol: bool):
    """Get audit context for a topic (for LLM prompts)."""
    kb_instance = KnowledgeBase()

    if protocol:
        ctx = kb_instance.get_protocol_context(topic)
    else:
        ctx = kb_instance.get_audit_context(topic)

    console.print(f"\n[bold]Audit Context: {topic}[/bold]\n")
    console.print(ctx)
