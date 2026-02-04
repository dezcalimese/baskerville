"""
Solodit integration commands.

Usage:
    ./hound.py solodit search <query>           # Search vulnerability database
    ./hound.py solodit checklist [--category]   # View security checklist
    ./hound.py solodit enrich <project>         # Enrich project hypotheses
"""

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent.parent))

from commands.project import ProjectManager
from extensions.solodit import SoloditClient, SoloditCache, HypothesisEnricher


console = Console()


@click.group("solodit")
def solodit():
    """Solodit vulnerability database integration."""
    pass


@solodit.command("search")
@click.argument("query")
@click.option("--impact", "-i", type=click.Choice(["HIGH", "MEDIUM", "LOW", "GAS"]), help="Filter by impact level")
@click.option("--tag", "-t", multiple=True, help="Filter by tag (can specify multiple)")
@click.option("--firm", "-f", multiple=True, help="Filter by audit firm (can specify multiple)")
@click.option("--limit", "-l", default=20, help="Maximum results")
@click.option("--page", "-p", default=1, help="Page number")
@click.option("--sort", "-s", type=click.Choice(["Recency", "Quality", "Rarity"]), default="Recency", help="Sort by")
def search(query: str, impact: str | None, tag: tuple, firm: tuple, limit: int, page: int, sort: str):
    """Search Solodit vulnerability database."""
    console.print(f"\n[bold]Searching Solodit for: {query}[/bold]\n")

    async def _search():
        client = SoloditClient()
        impact_filter = [impact] if impact else None
        tags_filter = list(tag) if tag else None
        firms_filter = list(firm) if firm else None

        findings, metadata = await client.search_findings(
            keywords=query,
            impact=impact_filter,
            tags=tags_filter,
            firms=firms_filter,
            page=page,
            page_size=min(limit, 100),
            sort_field=sort,
        )
        return findings[:limit], metadata

    findings, metadata = asyncio.run(_search())

    if not findings:
        console.print("[yellow]No findings found.[/yellow]")
        return

    total = metadata.get("totalResults", len(findings))
    rate_limit = metadata.get("rateLimit", {})

    console.print(f"Found {total} total results (showing {len(findings)})")
    if rate_limit:
        console.print(f"[dim]Rate limit: {rate_limit.get('remaining', '?')}/{rate_limit.get('limit', '?')} requests remaining[/dim]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Impact", width=8)
    table.add_column("Title", width=45)
    table.add_column("Protocol", width=12)
    table.add_column("Firm", width=12)
    table.add_column("Quality", width=7)

    for f in findings:
        impact_color = {
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "GAS": "dim",
        }.get(f.impact, "white")

        table.add_row(
            f"[{impact_color}]{f.impact}[/{impact_color}]",
            f.title[:45] + ("..." if len(f.title) > 45 else ""),
            (f.protocol_name[:12] + "..." if len(f.protocol_name) > 12 else f.protocol_name) if f.protocol_name else "-",
            (f.firm_name[:12] + "..." if len(f.firm_name) > 12 else f.firm_name) if f.firm_name else "-",
            f"{f.quality_score:.1f}",
        )

    console.print(table)

    if findings:
        console.print(f"\n[dim]View details: {findings[0].url.rsplit('/', 1)[0]}/<slug>[/dim]")


@solodit.command("checklist")
@click.option("--category", "-c", help="Filter by category (e.g., reentrancy, access-control)")
@click.option("--refresh", is_flag=True, help="Force refresh from GitHub")
def checklist(category: str | None, refresh: bool):
    """View Solodit security checklist."""
    console.print("\n[bold]Solodit Security Checklist[/bold]\n")

    cache = SoloditCache()

    try:
        data = cache.get_checklist_sync(force_refresh=refresh)
    except Exception as e:
        console.print(f"[red]Failed to load checklist: {e}[/red]")
        return

    if category:
        # Show specific category
        items = cache.get_checklist_category(category)
        if not items:
            console.print(f"[yellow]No items found for category: {category}[/yellow]")
            console.print(f"Available categories: {', '.join(data.keys())}")
            return

        console.print(f"[bold]{category}[/bold] ({len(items)} items)\n")

        for item in items[:20]:
            item_id = item.get("id", "?")
            question = item.get("question", "")
            console.print(f"  [{item_id}] {question}")

        if len(items) > 20:
            console.print(f"\n  ... and {len(items) - 20} more items")
    else:
        # Show categories overview
        table = Table(show_header=True, header_style="bold")
        table.add_column("Category", width=30)
        table.add_column("Items", width=10)
        table.add_column("Description", width=40)

        total_items = 0
        for cat_name, cat_data in data.items():
            items = cat_data.get("data", [])
            desc = cat_data.get("description", "")[:40]
            table.add_row(cat_name, str(len(items)), desc + "..." if desc else "-")
            total_items += len(items)

        console.print(table)
        console.print(f"\n[bold]Total: {total_items} checklist items[/bold]")
        console.print("\n[dim]Use --category to view items in a specific category[/dim]")


@solodit.command("enrich")
@click.argument("project_name")
@click.option("--limit", "-l", default=5, help="Max similar findings per hypothesis")
def enrich(project_name: str, limit: int):
    """Enrich project hypotheses with Solodit context."""
    console.print(f"\n[bold]Enriching hypotheses for: {project_name}[/bold]\n")

    # Load project
    manager = ProjectManager()
    project = manager.get_project(project_name)
    if not project:
        console.print(f"[red]Project '{project_name}' not found[/red]")
        raise SystemExit(1)

    project_dir = Path(project["path"])
    hypothesis_path = project_dir / "hypotheses.json"

    if not hypothesis_path.exists():
        console.print("[yellow]No hypotheses found for this project.[/yellow]")
        return

    import json
    with open(hypothesis_path) as f:
        store = json.load(f)

    hypotheses = list(store.get("hypotheses", {}).values())

    if not hypotheses:
        console.print("[yellow]No hypotheses in store.[/yellow]")
        return

    console.print(f"Found {len(hypotheses)} hypotheses to enrich\n")

    async def _enrich():
        enricher = HypothesisEnricher()
        results = await enricher.enrich_hypotheses(hypotheses, max_similar=limit)
        return results

    results = asyncio.run(_enrich())

    # Display results
    for result in results:
        hyp_id = result.hypothesis_id[:12]
        similar_count = len(result.similar_findings)
        checklist_count = len(result.checklist_matches)
        adj = result.confidence_adjustment

        if similar_count > 0 or checklist_count > 0:
            console.print(f"[bold]{hyp_id}[/bold]")
            console.print(f"  Similar findings: {similar_count}")
            console.print(f"  Checklist matches: {checklist_count}")
            if adj > 0:
                console.print(f"  Confidence boost: +{adj:.2f}")
            console.print()

    # Save enrichment data
    enrichment_path = project_dir / "solodit_enrichment.json"

    import json
    from datetime import datetime
    enrichment_data = {
        "enriched_at": datetime.now().isoformat(),
        "results": [r.to_dict() for r in results],
    }
    with open(enrichment_path, "w") as f:
        json.dump(enrichment_data, f, indent=2)

    console.print(f"[green]Enrichment saved to: {enrichment_path}[/green]")


@solodit.command("intel")
@click.argument("category")
@click.option("--limit", "-l", default=20, help="Max findings to retrieve")
def intel(category: str, limit: int):
    """Get pre-audit intelligence for a protocol category."""
    console.print(f"\n[bold]Pre-Audit Intelligence: {category}[/bold]\n")

    async def _get_intel():
        enricher = HypothesisEnricher()
        return await enricher.get_category_intelligence(category, limit=limit)

    data = asyncio.run(_get_intel())

    # Summary
    console.print(f"[bold]Findings:[/bold] {data['findings_count']}")
    console.print(f"[bold]Checklist Items:[/bold] {data['checklist_items']}")
    console.print()

    # Impact distribution
    console.print("[bold]Impact Distribution:[/bold]")
    for impact, count in data['severity_distribution'].items():
        if count > 0:
            bar = "█" * min(count, 20)
            console.print(f"  {impact:10} {bar} ({count})")
    console.print()

    # Top findings
    console.print("[bold]Top Findings:[/bold]")
    for f in data['top_findings'][:10]:
        impact = f.get('impact', f.get('severity', 'MEDIUM'))
        impact_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}.get(impact, "white")
        console.print(f"  [{impact_color}][{impact}][/{impact_color}] {f['title'][:60]}")
    console.print()

    # Checklist sample
    if data['checklist_sample']:
        console.print("[bold]Relevant Checklist Items:[/bold]")
        for item in data['checklist_sample']:
            q = item.get('question', '')[:70]
            console.print(f"  • {q}...")

    console.print(f"\n[dim]Run 'solodit checklist --category {category}' for full checklist[/dim]")
