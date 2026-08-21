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


def render_diff(result: dict, console: Console | None = None) -> None:
    """Human-readable view of a `diff_audits()` result (presentation only)."""
    console = console or Console()
    old, new = result["old"], result["new"]
    delta = result["score_delta"]

    header = Text()
    header.append("Score: ", style="bold")
    header.append(f"{old['score']}", style=_score_style(old["score"] or 0))
    header.append("  ->  ")
    header.append(f"{new['score']}", style=_score_style(new["score"] or 0))
    if delta is not None and delta != 0:
        header.append(f"  ({delta:+d})", style="bold green" if delta > 0 else "bold red")
    console.print(
        Panel(
            header,
            title=f"[bold]mcp-audit diff[/bold]  ·  {old['target']}  ->  {new['target']}",
            border_style=_score_style(new["score"] or 0),
        )
    )

    new_findings = result["new_findings"]
    if new_findings:
        table = Table(show_lines=True, expand=True, title=f"New findings ({len(new_findings)})")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Tool", no_wrap=True)
        table.add_column("Finding")
        for f in new_findings:
            detail = Text(f["message"] + "\n")
            detail.append("fix: ", style="dim")
            detail.append(f["recommendation"], style="green")
            table.add_row(
                Text(f["severity"], style=_SEVERITY_STYLE.get(f["severity"], "")),
                f["id"],
                f.get("tool_name") or "—",
                detail,
            )
        console.print(table)

    resolved = result["resolved_findings"]
    if resolved:
        console.print(
            "[green]Resolved:[/green] "
            + ", ".join(f"{f['id']} ({f.get('tool_name') or 'server'})" for f in resolved)
        )

    tools = result["tools"]
    if tools:
        for name in tools["added"]:
            console.print(f"[yellow]+ tool added:[/yellow] {name}")
        for name in tools["removed"]:
            console.print(f"[dim]- tool removed: {name}[/dim]")
        for ch in tools["changed"]:
            console.print(f"[yellow]~ tool changed:[/yellow] {ch['name']} ({', '.join(ch['changes'])})")
    elif tools is None:
        console.print("[dim]Tool-surface diff unavailable (a side is a JSON baseline).[/dim]")

    if result["rug_pull_signal"]:
        console.print(
            "[bold red]Rug-pull signal (MCP-T05):[/bold red] the tool surface changed "
            "between versions — re-review the added/changed tools before trusting this update."
        )

    if not new_findings and not resolved and not (tools and (tools["added"] or tools["removed"] or tools["changed"])):
        console.print("[bold green]✓ No changes between the two audits.[/bold green]")


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
    console.print(f"Evidence: {report.evidence_type}", style="dim")

    capability_rows = [tool for tool in report.tools or [] if tool.capabilities or tool.annotations]
    if capability_rows:
        capability_table = Table(show_lines=True, expand=True, title="Observed tool capabilities")
        capability_table.add_column("Tool", no_wrap=True)
        capability_table.add_column("Inferred from implementation")
        capability_table.add_column("Declared MCP annotations")
        for tool in capability_rows:
            inferred = ", ".join(sorted({item.capability for item in tool.capabilities})) or "—"
            declared = ", ".join(f"{key}={str(value).lower()}" for key, value in tool.annotations.items()) or "—"
            capability_table.add_row(tool.name, inferred, declared)
        console.print(capability_table)

    if report.policy:
        policy = report.policy
        decision = policy.get("decision", "manual_review")
        style = {"allow": "bold green", "deny": "bold red", "manual_review": "bold yellow"}.get(
            decision, "yellow"
        )
        identity = f"{policy.get('department')} / {policy.get('employee')}"
        if policy.get("agent"):
            identity += f" / {policy['agent']}"
        body = Text()
        body.append(f"Decision: {decision.upper()}\n", style=style)
        body.append("Effective allow: ", style="bold")
        body.append(", ".join(policy.get("effective_allow", [])) or "none")
        body.append("\nRequested: ", style="bold")
        body.append(", ".join(policy.get("requested", [])) or "none observed")
        unclassified = policy.get("coverage", {}).get("unclassified_tools", [])
        if unclassified:
            body.append("\nManual review (implementation unavailable): ", style="bold yellow")
            body.append(", ".join(unclassified))
        console.print(Panel(body, title=f"[bold]Privilege policy[/bold] · {identity}", border_style=style))

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
