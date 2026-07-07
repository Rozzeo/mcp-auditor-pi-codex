"""Command-line surface.

    mcp-audit <github-url | path> [--json] [--fail-on <severity>]   # audit (default)
    mcp-audit intel fetch | review | distill | build-docs            # threat intel
    mcp-audit update                                                 # refresh definitions

The audit path is a thin wrapper over `audit()`. In `--json` mode, stdout carries
ONLY the `AuditReport` JSON; all progress/errors go to stderr so output pipes
cleanly. `mcp-audit <target>` keeps working as before via a default-command group.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .core import audit
from .reporter import render_human
from .types import SEVERITY_ORDER

_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def _at_or_above(findings, threshold: str) -> bool:
    limit = _SEVERITY_RANK[threshold]
    return any(
        _SEVERITY_RANK.get(f.severity, 99) <= limit
        for f in findings
        if not f.suppressed
    )


def _intel_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".mcp-audit" / "intel"


def _default_queue_path() -> str:
    return str(_intel_dir() / "queue.jsonl")


class _DefaultGroup(click.Group):
    """Run the `audit` subcommand when the first token is not a known command.

    Keeps `mcp-audit <target> --json` working alongside `mcp-audit intel ...`
    and `mcp-audit update`.
    """

    default_cmd = "audit"

    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = [self.default_cmd, *args]
        return super().parse_args(ctx, args)


@click.group(
    cls=_DefaultGroup,
    name="mcp-audit",
    invoke_without_command=True,
    help="Statically audit MCP servers and curate the living MCP Threat Atlas.",
)
@click.pass_context
def main(ctx: click.Context) -> None:
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# --- audit (default command) ----------------------------------------------


@main.command(name="audit", help="Statically audit an MCP server for tool poisoning, over-privilege, and more.")
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, help="Emit the AuditReport as JSON on stdout (and nothing else).")
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER, case_sensitive=False),
    default=None,
    help="Exit non-zero if any finding at or above this severity exists (for CI gating).",
)
@click.option("--signatures", "signatures_path", type=click.Path(exists=True), default=None,
              help="Path to a custom signatures.yaml (pins the rule version).")
@click.option("--suppress", "suppressions_path", type=click.Path(exists=True), default=None,
              help="Auditor-side suppression file for reviewed false positives "
                   "(never read from inside the target).")
@click.option("--html", "html_path", type=click.Path(), default=None,
              help="Also write a self-contained HTML dashboard of the report to this path.")
def audit_cmd(
    target: str,
    as_json: bool,
    fail_on: str | None,
    signatures_path: str | None,
    suppressions_path: str | None,
    html_path: str | None,
) -> None:
    err = Console(stderr=True)
    try:
        report = audit(
            target,
            signatures_path=signatures_path,
            suppressions_path=suppressions_path,
        )
    except FileNotFoundError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2)
    except Exception as exc:  # network errors, malformed input, etc.
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2)

    if as_json:
        sys.stdout.write(json.dumps(report.to_dict(), indent=2) + "\n")
        sys.stdout.flush()
    else:
        render_human(report, Console())

    if html_path:
        from .htmlreport import render_html

        Path(html_path).write_text(render_html(report), encoding="utf-8")
        err.print(f"[green]HTML report written[/green] -> {html_path}")

    if fail_on:
        if report.is_mcp_server and _at_or_above(report.findings, fail_on.lower()):
            raise SystemExit(1)

    raise SystemExit(0)


# --- diff --------------------------------------------------------------------


@main.command(
    name="diff",
    help="Compare two audits of a server (old vs new version, or a saved --json "
         "report vs a live target) — the rug-pull detector.",
)
@click.argument("old_target")
@click.argument("new_target")
@click.option("--json", "as_json", is_flag=True, help="Emit the structured diff as JSON on stdout (and nothing else).")
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER, case_sensitive=False),
    default=None,
    help="Exit non-zero if any NEW finding at or above this severity appeared (for CI gating).",
)
@click.option("--signatures", "signatures_path", type=click.Path(exists=True), default=None,
              help="Path to a custom signatures.yaml (pins the rule version for both sides).")
@click.option("--suppress", "suppressions_path", type=click.Path(exists=True), default=None,
              help="Auditor-side suppression file, applied to both sides.")
def diff_cmd(
    old_target: str,
    new_target: str,
    as_json: bool,
    fail_on: str | None,
    signatures_path: str | None,
    suppressions_path: str | None,
) -> None:
    from .diffmode import diff_audits
    from .reporter import render_diff

    err = Console(stderr=True)
    try:
        result = diff_audits(
            old_target,
            new_target,
            signatures_path=signatures_path,
            suppressions_path=suppressions_path,
        )
    except FileNotFoundError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2)
    except Exception as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2)

    if as_json:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        sys.stdout.flush()
    else:
        render_diff(result, Console())

    if fail_on:
        limit = _SEVERITY_RANK[fail_on.lower()]
        if any(_SEVERITY_RANK.get(f["severity"], 99) <= limit for f in result["new_findings"]):
            raise SystemExit(1)

    raise SystemExit(0)


# --- playground --------------------------------------------------------------


@main.command(
    name="playground",
    help="Generate the interactive MCP Security Playground HTML (paste a tool, see findings live).",
)
@click.option("--out", "out_path", default="mcp-playground.html", show_default=True, help="Output HTML path.")
@click.option("--signatures", "signatures_path", type=click.Path(exists=True), default=None,
              help="Path to a custom signatures.yaml (pins the embedded rule version).")
def playground_cmd(out_path: str, signatures_path: str | None) -> None:
    from .playground import build_playground
    from .rules import load_signatures
    from .updater import effective_signatures_path

    err = Console(stderr=True)
    signatures = load_signatures(effective_signatures_path(signatures_path))
    Path(out_path).write_text(build_playground(signatures), encoding="utf-8")
    err.print(
        f"[green]Playground written[/green] -> {out_path} "
        f"(signatures v{signatures.get('version')}). Open it in a browser."
    )
    raise SystemExit(0)


# --- update ----------------------------------------------------------------


@main.command(name="update", help="Download the latest threat definitions (Atlas + signatures) into the local cache.")
def update_cmd() -> None:
    from .updater import update

    err = Console(stderr=True)
    try:
        result = update()
    except Exception as exc:
        err.print(f"[red]update failed:[/red] {exc}")
        raise SystemExit(2)
    err.print(
        f"[green]Definitions updated[/green] -> {result['dest']} "
        f"(signature version {result['version']})."
    )
    raise SystemExit(0)


# --- intel group -----------------------------------------------------------


@main.group(name="intel", help="Living threat-intelligence: fetch new research/CVEs, review, and build docs.")
def intel_group() -> None:
    pass


@intel_group.command(name="fetch", help="Fetch new candidate threats (arXiv + CVE feeds) into the review queue.")
@click.option("--queue", "queue_path", default=None, help="Review-queue JSONL path (default: ~/.mcp-audit/intel/queue.jsonl).")
@click.option("--max-results", default=20, show_default=True, help="Max arXiv results to pull.")
@click.option("--no-arxiv", is_flag=True, help="Skip the arXiv source.")
@click.option("--no-cve", is_flag=True, help="Skip the CVE/advisory source.")
def intel_fetch(queue_path: str | None, max_results: int, no_arxiv: bool, no_cve: bool) -> None:
    from .intel import advisories, arxiv
    from .intel import queue as q

    err = Console(stderr=True)
    path = queue_path or _default_queue_path()
    fetched = []
    if not no_arxiv:
        try:
            fetched += arxiv.fetch(max_results=max_results)
        except Exception as exc:
            err.print(f"[yellow]arxiv fetch failed:[/yellow] {exc}")
    if not no_cve:
        try:
            fetched += advisories.fetch()
        except Exception as exc:
            err.print(f"[yellow]cve fetch failed:[/yellow] {exc}")

    new = q.add_candidates(path, fetched)
    err.print(
        f"[green]{len(new)} new candidate(s)[/green] queued at {path} "
        f"({len(fetched)} fetched, deduped against the Atlas)."
    )
    raise SystemExit(0)


@intel_group.command(name="review", help="Show the current intel review queue.")
@click.option("--queue", "queue_path", default=None, help="Review-queue JSONL path.")
def intel_review(queue_path: str | None) -> None:
    from .intel import queue as q

    console = Console()
    items = q.load_queue(queue_path or _default_queue_path())
    if not items:
        console.print("[dim]Review queue is empty. Run `mcp-audit intel fetch` first.[/dim]")
        raise SystemExit(0)

    table = Table(show_lines=True, title="MCP intel review queue")
    table.add_column("Source", no_wrap=True)
    table.add_column("Id", no_wrap=True)
    table.add_column("Title")
    table.add_column("Matched", no_wrap=True)
    for c in items:
        table.add_row(c.source, c.ident or "—", c.title, ", ".join(c.matched[:3]))
    console.print(table)
    console.print(f"[dim]{len(items)} item(s). Curate by hand into signatures.yaml + threats.yaml.[/dim]")
    raise SystemExit(0)


@intel_group.command(name="distill", help="Draft candidate detection patterns from queued abstracts (optional --use-llm).")
@click.option("--queue", "queue_path", default=None, help="Review-queue JSONL path.")
@click.option("--use-llm", is_flag=True, help="Enable LLM drafting (OFF by default; sees abstracts only).")
def intel_distill(queue_path: str | None, use_llm: bool) -> None:
    from .intel import distill as d
    from .intel import queue as q

    console = Console()
    items = q.load_queue(queue_path or _default_queue_path())
    if not items:
        console.print("[dim]Review queue is empty.[/dim]")
        raise SystemExit(0)
    cache = str(_intel_dir() / "distill-cache")
    for c in items:
        result = d.distill(c, use_llm=use_llm, cache_dir=cache)
        console.print(f"[bold]{c.ident or c.source}[/bold]  {c.title}")
        console.print_json(data=result)
    raise SystemExit(0)


@intel_group.command(name="build-docs", help="Generate the MCP Threat Encyclopedia HTML from the Atlas.")
@click.option("--out", "out_path", default="mcp-threat-encyclopedia.html", show_default=True, help="Output HTML path.")
@click.option("--atlas", "atlas_path", type=click.Path(exists=True), default=None, help="Custom threats.yaml path.")
def intel_build_docs(out_path: str, atlas_path: str | None) -> None:
    from .atlas import load_atlas
    from .encyclopedia import build_encyclopedia

    err = Console(stderr=True)
    try:
        atlas = load_atlas(atlas_path)
    except Exception as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2)
    Path(out_path).write_text(build_encyclopedia(atlas), encoding="utf-8")
    err.print(f"[green]Wrote[/green] {out_path} ({len(atlas.get('threats', []))} threats).")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
