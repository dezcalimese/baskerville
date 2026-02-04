"""
Bounty workflow CLI commands.

Usage:
    ./hound.py bounty discover [--platform <platform>]    # Discover active contests
    ./hound.py bounty list [--active] [--platform]        # List tracked contests
    ./hound.py bounty show <contest-id>                   # Show contest details
    ./hound.py bounty add <url>                           # Add contest manually
    ./hound.py bounty scope <contest-id>                  # Download/view scope
    ./hound.py bounty link <contest-id> <project>         # Link to Hound project
    ./hound.py bounty import <contest-id>                 # Import findings from project
    ./hound.py bounty review <contest-id>                 # Interactive review workflow
    ./hound.py bounty export <contest-id>                 # Export for submission
    ./hound.py bounty stats                               # Show statistics
"""

import sys
import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax

sys.path.insert(0, str(Path(__file__).parent.parent))

from extensions.bounty import (
    Contest, ContestState, Finding, FindingState, Severity,
    ContestScraper, BountyStorage, get_formatter, FORMATTERS
)


console = Console()


def get_storage() -> BountyStorage:
    """Get the bounty storage instance."""
    return BountyStorage()


@click.group("bounty")
def bounty():
    """Bounty workflow for audit contests."""
    pass


@bounty.command("discover")
@click.option("--platform", "-p", type=click.Choice(ContestScraper.available_platforms()), help="Specific platform")
@click.option("--save", "-s", is_flag=True, help="Save discovered contests")
def discover(platform: str | None, save: bool):
    """Discover active contests from platforms."""
    console.print("\n[bold]Discovering Active Contests[/bold]\n")

    async def run():
        async with ContestScraper() as scraper:
            if platform:
                console.print(f"[dim]Scraping {platform}...[/dim]")
                results = {platform: await scraper.scrape_platform(platform)}
            else:
                console.print("[dim]Scraping all platforms...[/dim]")
                results = await scraper.scrape_all()

            storage = get_storage() if save else None
            total = 0

            for plat, contests in results.items():
                if not contests:
                    continue

                console.print(f"\n[bold cyan]{plat.upper()}[/bold cyan] ({len(contests)} found)")

                table = Table(show_header=True, header_style="bold")
                table.add_column("Name", width=40)
                table.add_column("Prize Pool", width=15)
                table.add_column("End Date", width=12)
                table.add_column("Status", width=10)

                for sc in contests:
                    contest = sc.to_contest()
                    end_str = contest.end_date.strftime("%Y-%m-%d") if contest.end_date else "Unknown"
                    status = "Active" if contest.is_in_progress else "Ended"

                    table.add_row(
                        contest.name[:40],
                        contest.prize_pool or "-",
                        end_str,
                        f"[green]{status}[/green]" if status == "Active" else f"[dim]{status}[/dim]",
                    )

                    if save and storage:
                        # Check if already tracked
                        existing = storage.get_contest_by_url(contest.url)
                        if not existing:
                            storage.save_contest(contest)
                            total += 1

                console.print(table)

            if save:
                console.print(f"\n[green]Saved {total} new contests[/green]")

    asyncio.run(run())


@bounty.command("list")
@click.option("--active", "-a", is_flag=True, help="Show only active contests")
@click.option("--platform", "-p", help="Filter by platform")
@click.option("--state", "-s", type=click.Choice([s.value for s in ContestState]), help="Filter by state")
def list_contests(active: bool, platform: str | None, state: str | None):
    """List tracked contests."""
    console.print("\n[bold]Tracked Contests[/bold]\n")

    storage = get_storage()
    state_filter = ContestState(state) if state else None
    contests = storage.list_contests(platform=platform, state=state_filter, active_only=active)

    if not contests:
        console.print("[yellow]No contests found.[/yellow]")
        console.print("[dim]Run 'bounty discover --save' to find contests.[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", width=25)
    table.add_column("Platform", width=12)
    table.add_column("Name", width=30)
    table.add_column("State", width=12)
    table.add_column("Findings", width=10)
    table.add_column("Time Left", width=10)

    for contest in contests:
        stats = storage.contest_stats(contest.id)
        findings_str = f"{stats['accepted']}/{stats['total_findings']}"

        state_color = {
            ContestState.DISCOVERED: "dim",
            ContestState.SCOPED: "blue",
            ContestState.AUDITING: "yellow",
            ContestState.REVIEW: "cyan",
            ContestState.EXPORTED: "green",
            ContestState.SUBMITTED: "green",
            ContestState.ARCHIVED: "dim",
        }.get(contest.state, "white")

        table.add_row(
            contest.id[:25],
            contest.platform,
            contest.name[:30],
            f"[{state_color}]{contest.state.value}[/{state_color}]",
            findings_str,
            contest.time_remaining,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(contests)} contests[/dim]")


@bounty.command("show")
@click.argument("contest_id")
def show(contest_id: str):
    """Show contest details."""
    storage = get_storage()
    contest = storage.load_contest(contest_id)

    if not contest:
        console.print(f"[red]Contest not found: {contest_id}[/red]")
        return

    # Contest info panel
    info = f"""
[bold]Platform:[/bold] {contest.platform}
[bold]URL:[/bold] {contest.url}
[bold]State:[/bold] {contest.state.value}
[bold]Time Remaining:[/bold] {contest.time_remaining}

[bold]Prize Pool:[/bold] {contest.prize_pool or 'Unknown'}
[bold]Start:[/bold] {contest.start_date.strftime('%Y-%m-%d %H:%M') if contest.start_date else 'Unknown'}
[bold]End:[/bold] {contest.end_date.strftime('%Y-%m-%d %H:%M') if contest.end_date else 'Unknown'}
"""

    if contest.repo_url:
        info += f"[bold]Repository:[/bold] {contest.repo_url}\n"
    if contest.docs_url:
        info += f"[bold]Docs:[/bold] {contest.docs_url}\n"
    if contest.project_name:
        info += f"\n[bold]Linked Project:[/bold] {contest.project_name}"

    console.print(Panel(info, title=f"[bold]{contest.name}[/bold]", border_style="cyan"))

    # Findings summary
    stats = storage.contest_stats(contest.id)
    if stats["total_findings"] > 0:
        console.print("\n[bold]Findings Summary[/bold]")

        findings_table = Table(show_header=True, header_style="bold")
        findings_table.add_column("Severity", width=15)
        findings_table.add_column("Count", width=10)

        for sev in ["critical", "high", "medium", "low", "informational", "gas"]:
            count = stats["by_severity"].get(sev, 0)
            if count > 0:
                findings_table.add_row(sev.capitalize(), str(count))

        console.print(findings_table)

        console.print(f"\n[dim]Accepted: {stats['accepted']} | Rejected: {stats['rejected']} | Pending: {stats['pending_review']}[/dim]")


@bounty.command("add")
@click.argument("url")
@click.option("--platform", "-p", type=click.Choice(ContestScraper.available_platforms()), help="Platform (auto-detected if not specified)")
@click.option("--name", "-n", help="Contest name")
def add(url: str, platform: str | None, name: str | None):
    """Add a contest manually."""
    storage = get_storage()

    # Check if already exists
    existing = storage.get_contest_by_url(url)
    if existing:
        console.print(f"[yellow]Contest already tracked: {existing.id}[/yellow]")
        return

    # Auto-detect platform from URL
    if not platform:
        url_lower = url.lower()
        if "code4rena" in url_lower:
            platform = "code4rena"
        elif "sherlock" in url_lower:
            platform = "sherlock"
        elif "codehawks" in url_lower:
            platform = "codehawks"
        elif "immunefi" in url_lower:
            platform = "immunefi"
        else:
            platform = Prompt.ask("Platform", choices=ContestScraper.available_platforms())

    # Get name if not provided
    if not name:
        name = Prompt.ask("Contest name")

    # Create contest
    import re
    slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
    contest_id = f"{platform}-{slug}"

    contest = Contest(
        id=contest_id,
        platform=platform,
        name=name,
        url=url,
    )

    storage.save_contest(contest)
    console.print(f"[green]Added contest: {contest_id}[/green]")


@bounty.command("link")
@click.argument("contest_id")
@click.argument("project_name")
def link(contest_id: str, project_name: str):
    """Link contest to a Hound project."""
    storage = get_storage()
    contest = storage.load_contest(contest_id)

    if not contest:
        console.print(f"[red]Contest not found: {contest_id}[/red]")
        return

    # Check if project exists
    project_path = Path.home() / ".hound" / "projects" / project_name
    if not project_path.exists():
        console.print(f"[red]Project not found: {project_name}[/red]")
        console.print("[dim]Create it with: hound project create <name> /path/to/code[/dim]")
        return

    contest.project_name = project_name
    contest.project_path = str(project_path)

    # Transition to SCOPED if in DISCOVERED
    if contest.state == ContestState.DISCOVERED:
        contest.transition_to(ContestState.SCOPED)

    storage.save_contest(contest)
    console.print(f"[green]Linked {contest_id} to project {project_name}[/green]")


@bounty.command("import")
@click.argument("contest_id")
@click.option("--force", "-f", is_flag=True, help="Re-import all findings")
def import_findings(contest_id: str, force: bool):
    """Import findings from linked Hound project."""
    storage = get_storage()
    contest = storage.load_contest(contest_id)

    if not contest:
        console.print(f"[red]Contest not found: {contest_id}[/red]")
        return

    if not contest.project_path:
        console.print("[red]Contest not linked to a project. Use 'bounty link' first.[/red]")
        return

    # Find hypotheses file
    hypotheses_path = Path(contest.project_path) / "hypotheses.json"
    if not hypotheses_path.exists():
        console.print("[yellow]No hypotheses found in project.[/yellow]")
        console.print("[dim]Run an audit first: hound agent audit <project>[/dim]")
        return

    # Import
    if force:
        # Clear existing findings
        for finding in storage.iter_findings(contest_id):
            storage.delete_finding(contest_id, finding.id)

    findings = storage.import_hypotheses(contest_id, hypotheses_path)

    if findings:
        console.print(f"[green]Imported {len(findings)} new findings[/green]")

        # Show summary by severity
        by_sev = {}
        for f in findings:
            sev = f.severity.value
            by_sev[sev] = by_sev.get(sev, 0) + 1

        for sev, count in sorted(by_sev.items()):
            console.print(f"  {sev}: {count}")

        # Transition contest state if needed
        if contest.state in [ContestState.SCOPED, ContestState.DISCOVERED]:
            contest.transition_to(ContestState.SCOPED)
            contest.transition_to(ContestState.AUDITING)
            storage.save_contest(contest)
    else:
        console.print("[yellow]No new findings to import.[/yellow]")


@bounty.command("review")
@click.argument("contest_id")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low"]), help="Filter by severity")
def review(contest_id: str, severity: str | None):
    """Interactive review workflow for findings."""
    storage = get_storage()
    contest = storage.load_contest(contest_id)

    if not contest:
        console.print(f"[red]Contest not found: {contest_id}[/red]")
        return

    # Get findings needing review
    findings = storage.list_findings(contest_id, state=FindingState.DETECTED)
    findings += storage.list_findings(contest_id, state=FindingState.TRIAGED)

    if severity:
        findings = [f for f in findings if f.severity.value == severity]

    if not findings:
        console.print("[green]No findings pending review.[/green]")
        return

    console.print(f"\n[bold]Review Mode: {len(findings)} findings to review[/bold]")
    console.print("[dim]Commands: (a)ccept, (r)eject, (s)kip, (e)dit, (q)uit[/dim]\n")

    for i, finding in enumerate(findings, 1):
        console.print(f"\n[bold cyan]Finding {i}/{len(findings)}[/bold cyan]")
        console.print(Panel(
            f"""[bold]{finding.title}[/bold]
[{finding.severity.value.upper()}] {finding.vulnerability_type or 'Unknown type'}

{finding.description[:500]}{'...' if len(finding.description) > 500 else ''}

[dim]Location: {finding.file_path or 'Unknown'}[/dim]
[dim]Confidence: {finding.confidence:.0%}[/dim]
""",
            title=f"[{finding.severity.value}] {finding.id}",
            border_style="yellow" if finding.severity in [Severity.HIGH, Severity.CRITICAL] else "blue"
        ))

        if finding.code_snippet:
            console.print("[bold]Code:[/bold]")
            console.print(Syntax(finding.code_snippet[:500], "solidity", theme="monokai", line_numbers=True))

        # Get action
        action = Prompt.ask(
            "Action",
            choices=["a", "r", "s", "e", "q", "accept", "reject", "skip", "edit", "quit"],
            default="s"
        )

        if action in ["q", "quit"]:
            break
        elif action in ["a", "accept"]:
            notes = Prompt.ask("Notes (optional)", default="")
            finding.accept(notes)
            storage.save_finding(finding)
            console.print("[green]Accepted[/green]")
        elif action in ["r", "reject"]:
            reason = Prompt.ask("Rejection reason")
            finding.reject(reason)
            storage.save_finding(finding)
            console.print("[red]Rejected[/red]")
        elif action in ["e", "edit"]:
            # Edit finding details
            new_title = Prompt.ask("Title", default=finding.title)
            new_sev = Prompt.ask("Severity", choices=["critical", "high", "medium", "low", "informational", "gas"], default=finding.severity.value)
            new_desc = Prompt.ask("Description (enter to keep)", default="")

            finding.title = new_title
            finding.severity = Severity(new_sev)
            if new_desc:
                finding.description = new_desc
            storage.save_finding(finding)
            console.print("[blue]Updated[/blue]")
        # skip does nothing

    # Update contest state after review
    if contest.state == ContestState.AUDITING:
        accepted = len(storage.list_findings(contest_id, state=FindingState.ACCEPTED))
        if accepted > 0:
            contest.transition_to(ContestState.REVIEW)
            storage.save_contest(contest)

    console.print("\n[bold]Review session complete.[/bold]")


@bounty.command("export")
@click.argument("contest_id")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--format", "-f", "fmt", type=click.Choice(["individual", "report", "both"]), default="individual", help="Export format")
def export(contest_id: str, output: str | None, fmt: str):
    """Export findings for platform submission."""
    storage = get_storage()
    contest = storage.load_contest(contest_id)

    if not contest:
        console.print(f"[red]Contest not found: {contest_id}[/red]")
        return

    # Get exportable findings (accepted or refined)
    findings = storage.get_exportable_findings(contest_id)
    accepted = storage.list_findings(contest_id, state=FindingState.ACCEPTED)
    findings = list(set(findings + accepted))

    if not findings:
        console.print("[yellow]No findings ready for export.[/yellow]")
        console.print("[dim]Review and accept findings first: bounty review <contest-id>[/dim]")
        return

    # Get formatter
    try:
        formatter = get_formatter(contest.platform)
    except ValueError:
        console.print(f"[yellow]No formatter for {contest.platform}, using code4rena format[/yellow]")
        formatter = get_formatter("code4rena")

    # Setup output directory
    output_dir = Path(output) if output else Path.home() / ".hound" / "bounty" / "exports" / contest_id
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]Exporting {len(findings)} findings for {contest.platform}[/bold]\n")

    if fmt in ["individual", "both"]:
        # Export individual findings
        for finding in findings:
            formatted = formatter.format_finding(finding)
            filename = f"{finding.severity.value}_{finding.id}.md"
            filepath = output_dir / filename
            filepath.write_text(formatted.to_markdown())
            console.print(f"  [green]Exported:[/green] {filename}")

            # Mark as exported
            if finding.state != FindingState.EXPORTED:
                finding.transition_to(FindingState.REFINED)
                finding.transition_to(FindingState.EXPORTED)
                storage.save_finding(finding)

    if fmt in ["report", "both"]:
        # Export full report (if formatter supports it)
        if hasattr(formatter, "format_full_report"):
            report = formatter.format_full_report(contest.name, findings)
            report_path = output_dir / "full_report.md"
            report_path.write_text(report)
            console.print(f"\n  [green]Full report:[/green] {report_path}")

    # Update contest state
    if contest.state in [ContestState.REVIEW, ContestState.AUDITING]:
        contest.transition_to(ContestState.REVIEW)
        contest.transition_to(ContestState.EXPORTED)
        storage.save_contest(contest)

    console.print(f"\n[bold green]Export complete![/bold green]")
    console.print(f"[dim]Output directory: {output_dir}[/dim]")
    console.print("\n[yellow]IMPORTANT: Review exports and submit manually to the platform.[/yellow]")
    console.print("[yellow]Baskerville never auto-submits findings.[/yellow]")


@bounty.command("submit")
@click.argument("contest_id")
@click.option("--notes", "-n", help="Submission notes")
def submit(contest_id: str, notes: str | None):
    """Mark contest as submitted (manual confirmation)."""
    storage = get_storage()
    contest = storage.load_contest(contest_id)

    if not contest:
        console.print(f"[red]Contest not found: {contest_id}[/red]")
        return

    if contest.state != ContestState.EXPORTED:
        console.print(f"[yellow]Contest not in exported state (current: {contest.state.value})[/yellow]")
        if not Confirm.ask("Mark as submitted anyway?"):
            return

    # Confirm submission
    console.print("\n[bold yellow]Submission Confirmation[/bold yellow]")
    console.print("[dim]This marks the contest as submitted. Ensure you've actually submitted on the platform.[/dim]\n")

    stats = storage.contest_stats(contest_id)
    console.print(f"  Findings exported: {stats.get('by_state', {}).get('exported', 0)}")
    console.print(f"  Platform: {contest.platform}")
    console.print(f"  URL: {contest.url}")

    if not Confirm.ask("\nConfirm manual submission complete?"):
        return

    contest.submission_notes = notes or ""
    contest.transition_to(ContestState.SUBMITTED)
    storage.save_contest(contest)

    console.print("\n[bold green]Contest marked as submitted![/bold green]")


@bounty.command("stats")
def stats():
    """Show bounty statistics."""
    storage = get_storage()
    stats = storage.global_stats()

    console.print("\n[bold]Bounty Statistics[/bold]\n")

    # Overview table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric", width=25)
    table.add_column("Value", width=15)

    table.add_row("Total Contests", str(stats["total_contests"]))
    table.add_row("Total Findings", str(stats["total_findings"]))
    table.add_row("Accepted Findings", str(stats["total_accepted"]))
    table.add_row("Exported Findings", str(stats["total_exported"]))

    console.print(table)

    # By platform
    if stats["contests_by_platform"]:
        console.print("\n[bold]By Platform[/bold]")
        for plat, count in sorted(stats["contests_by_platform"].items()):
            console.print(f"  {plat}: {count}")

    # By state
    if stats["contests_by_state"]:
        console.print("\n[bold]By State[/bold]")
        for state, count in sorted(stats["contests_by_state"].items()):
            console.print(f"  {state}: {count}")


@bounty.command("archive")
@click.argument("contest_id")
def archive(contest_id: str):
    """Archive a contest."""
    storage = get_storage()
    contest = storage.load_contest(contest_id)

    if not contest:
        console.print(f"[red]Contest not found: {contest_id}[/red]")
        return

    if contest.state == ContestState.ARCHIVED:
        console.print("[yellow]Contest already archived.[/yellow]")
        return

    if Confirm.ask(f"Archive contest '{contest.name}'?"):
        contest.transition_to(ContestState.ARCHIVED)
        storage.save_contest(contest)
        console.print("[green]Contest archived.[/green]")
