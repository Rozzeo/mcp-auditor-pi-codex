"""Human-readable terminal reporter (spec §8).

A thin presentation layer over `AuditReport`. Uses `rich` for colored output.
Carries no detection logic.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .types import SEVERITY_ORDER, AuditReport

_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _cite(finding) -> str:
    """A short human citation string from a finding's first source, if any."""
    for src in finding.sources or []:
        if src.get("section"):
            arx = f" arXiv:{src['arxiv']}" if src.get("arxiv") else ""
            return f"paper §{src['section']}{arx}"
        if src.get("id"):
            name = f" {src['name']}" if src.get("name") else ""
            return f"{src['id']}{name}"
    return ""


def _score_style(score: int) -> str:
    if score >= 80:
        return "bold green"
    if score >= 50:
        return "bold yellow"
    return "bold red"


def render_human(report: AuditReport, console: Console | None = None) -> None:
    console = console or Console()

    if not report.is_mcp_server:
        console.print(
            Panel(
                Text(report.message or "Not an MCP server.", style="yellow"),
                title=f"[bold]mcp-audit[/bold]  ·  {report.target}",
                border_style="yellow",
            )
        )
        return

    score = report.score if report.score is not None else 0
    header = Text()
    header.append("Security score: ", style="bold")
    header.append(f"{score}/100", style=_score_style(score))
    console.print(
        Panel(header, title=f"[bold]mcp-audit[/bold]  ·  {report.target}", border_style=_score_style(score))
    )

    summary = report.summary()
    counts = Table.grid(padding=(0, 2))
    counts.add_row(
        *[Text(f"{sev}: {summary[sev]}", style=_SEVERITY_STYLE[sev]) for sev in SEVERITY_ORDER]
    )
    console.print(counts)
    console.print(f"Tools analyzed: {report.tools_analyzed}", style="dim")

    if not report.findings:
        console.print("\n[bold green]✓ No findings.[/bold green] This server looks clean.")
        return

    console.print()
    table = Table(show_lines=True, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Tool", no_wrap=True)
    table.add_column("Location", no_wrap=True)
    table.add_column("Finding")

    for f in report.findings:
        detail = Text()
        if f.suppressed:
            detail.append("SUPPRESSED: ", style="bold dim")
            detail.append((f.suppress_reason or "") + "\n", style="dim italic")
        detail.append(f.message + "\n")
        if f.evidence:
            detail.append("evidence: ", style="dim")
            detail.append(f.evidence + "\n", style="italic")
        if f.threat_id:
            cite = _cite(f)
            detail.append("threat: ", style="dim")
            detail.append(f.threat_id + (f" · {cite}" if cite else "") + "\n", style="magenta")
        detail.append("fix: ", style="dim")
        detail.append(f.recommendation, style="green")
        severity_label = Text(f.severity, style="dim strike" if f.suppressed else _SEVERITY_STYLE.get(f.severity, ""))
        if f.confidence and not f.suppressed:
            severity_label.append(f"\n({f.confidence})", style="dim")
        table.add_row(
            severity_label,
            f.id,
            f.tool_name or "—",
            f.location or "—",
            detail,
        )
    console.print(table)
