"""
Static analysis command for running Slither and Aderyn.

Usage:
    ./hound.py static <project_name> [--tool slither|aderyn|all] [--import]
"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from commands.project import ProjectManager
from extensions.static import StaticAnalysisPipeline


console = Console()


@click.command("static")
@click.argument("project_name")
@click.option(
    "--tool",
    type=click.Choice(["slither", "aderyn", "all"]),
    default="all",
    help="Which tool(s) to run",
)
@click.option(
    "--import-hypotheses",
    is_flag=True,
    help="Import findings into hypothesis store",
)
@click.option(
    "--min-severity",
    type=click.Choice(["high", "medium", "low", "info"]),
    default="low",
    help="Minimum severity to include",
)
@click.option(
    "--no-dedup",
    is_flag=True,
    help="Disable deduplication across tools",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Show debug information",
)
def static(
    project_name: str,
    tool: str,
    import_hypotheses: bool,
    min_severity: str,
    no_dedup: bool,
    debug: bool,
):
    """Run static analysis on a project.

    Runs Slither and/or Aderyn to find vulnerabilities,
    then optionally imports findings into Hound's hypothesis store.
    """
    # Load project
    manager = ProjectManager()
    project = manager.get_project(project_name)
    if not project:
        console.print(f"[red]Project '{project_name}' not found[/red]")
        raise SystemExit(1)

    source_path = Path(project["source_path"])
    project_dir = Path(project["path"])

    console.print(f"\n[bold]Static Analysis: {project_name}[/bold]")
    console.print(f"Source: {source_path}\n")

    # Map severity names
    severity_map = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }

    # Configure pipeline
    slither_config = {
        "min_impact": severity_map.get(min_severity, "Low"),
        "min_confidence": "Low",
    }
    aderyn_config = {
        "min_severity": severity_map.get(min_severity, "Low"),
    }

    pipeline = StaticAnalysisPipeline(
        slither_config=slither_config if tool in ["slither", "all"] else None,
        aderyn_config=aderyn_config if tool in ["aderyn", "all"] else None,
        deduplicate=not no_dedup,
    )

    # Check tool availability
    console.print("[dim]Checking tools...[/dim]")
    tools = pipeline.check_tools()

    tool_table = Table(show_header=True, header_style="bold")
    tool_table.add_column("Tool")
    tool_table.add_column("Status")
    tool_table.add_column("Version/Error")

    for tool_name, (available, info) in tools.items():
        if tool in ["all", tool_name]:
            status = "[green]Available[/green]" if available else "[red]Not found[/red]"
            tool_table.add_row(tool_name.title(), status, info)

    console.print(tool_table)
    console.print()

    # Check if any selected tools are available
    selected_available = any(
        available
        for name, (available, _) in tools.items()
        if tool in ["all", name]
    )

    if not selected_available:
        console.print("[red]No selected tools are available. Install with:[/red]")
        console.print("  Slither: pip install slither-analyzer")
        console.print("  Aderyn: cyfrinup (or npm install @cyfrin/aderyn -g)")
        raise SystemExit(1)

    # Run analysis
    console.print("[bold]Running static analysis...[/bold]")

    result = pipeline.run(source_path)

    # Display results
    console.print(f"\n[bold]Results:[/bold]")

    results_table = Table(show_header=True, header_style="bold")
    results_table.add_column("Source")
    results_table.add_column("Findings")
    results_table.add_column("Status")

    slither_meta = result.metadata.get("tools", {}).get("slither", {})
    aderyn_meta = result.metadata.get("tools", {}).get("aderyn", {})

    if tool in ["slither", "all"]:
        slither_status = (
            "[green]Success[/green]"
            if slither_meta.get("success")
            else f"[red]{slither_meta.get('error', 'Failed')}[/red]"
        )
        results_table.add_row(
            "Slither", str(len(result.slither_findings)), slither_status
        )

    if tool in ["aderyn", "all"]:
        aderyn_status = (
            "[green]Success[/green]"
            if aderyn_meta.get("success")
            else f"[red]{aderyn_meta.get('error', 'Failed')}[/red]"
        )
        results_table.add_row(
            "Aderyn", str(len(result.aderyn_findings)), aderyn_status
        )

    console.print(results_table)

    # Show hypotheses summary
    if result.hypotheses:
        console.print(f"\n[bold]Unique Hypotheses: {len(result.hypotheses)}[/bold]")

        # Count by severity
        by_severity = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for hyp in result.hypotheses:
            sev = hyp.get("severity", "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        severity_str = ", ".join(
            f"{k}: {v}" for k, v in by_severity.items() if v > 0
        )
        console.print(f"  By severity: {severity_str}")

        # Show top findings
        if debug:
            console.print("\n[bold]Top Findings:[/bold]")
            for hyp in sorted(
                result.hypotheses,
                key=lambda h: {"high": 0, "medium": 1, "low": 2, "info": 3}.get(
                    h.get("severity", "medium"), 2
                ),
            )[:10]:
                sev = hyp.get("severity", "medium")
                sev_color = {
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "dim",
                }.get(sev, "white")
                console.print(
                    f"  [{sev_color}][{sev.upper()}][/{sev_color}] {hyp.get('title', 'Unknown')}"
                )

    # Save results
    static_dir = project_dir / "static_analysis"
    paths = pipeline.save_results(result, static_dir)
    console.print(f"\n[dim]Results saved to: {static_dir}[/dim]")

    # Import to hypothesis store if requested
    if import_hypotheses and result.hypotheses:
        hypothesis_path = project_dir / "hypotheses.json"
        imported = pipeline.import_to_hypothesis_store(result, hypothesis_path)
        console.print(
            f"\n[green]Imported {imported} hypotheses to store[/green]"
        )

    console.print("\n[bold green]Static analysis complete![/bold green]")
