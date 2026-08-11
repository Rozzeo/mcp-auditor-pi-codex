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

from .core import audit, audit_detailed
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
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None,
              help="Auditor-side department privilege policy (never read from the target).")
@click.option("--employee", default=None,
              help="Employee identity from --policy; required unless --agent selects it.")
@click.option("--agent", default=None,
              help="Main/helper agent identity from --policy; inherits and narrows employee privileges.")
@click.option("--html", "html_path", type=click.Path(), default=None,
              help="Also write a self-contained HTML dashboard of the report to this path.")
def audit_cmd(
    target: str,
    as_json: bool,
    fail_on: str | None,
    signatures_path: str | None,
    suppressions_path: str | None,
    policy_path: str | None,
    employee: str | None,
    agent: str | None,
    html_path: str | None,
) -> None:
    err = Console(stderr=True)
    try:
        report = audit(
            target,
            signatures_path=signatures_path,
            suppressions_path=suppressions_path,
            policy_path=policy_path,
            employee=employee,
            agent=agent,
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
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None,
              help="Department privilege policy, applied to both sides.")
@click.option("--employee", default=None, help="Employee identity from --policy.")
@click.option("--agent", default=None, help="Main/helper agent identity from --policy.")
def diff_cmd(
    old_target: str,
    new_target: str,
    as_json: bool,
    fail_on: str | None,
    signatures_path: str | None,
    suppressions_path: str | None,
    policy_path: str | None,
    employee: str | None,
    agent: str | None,
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
            policy_path=policy_path,
            employee=employee,
            agent=agent,
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


@main.command(
    name="installed",
    help="List the MCP servers registered in this machine's client configs and flag risky launch specs.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the inventory as JSON on stdout (and nothing else).")
@click.option("--fail-on", type=click.Choice(SEVERITY_ORDER, case_sensitive=False), default=None,
              help="Exit non-zero if any finding at or above this severity exists (for CI gating).")
def installed_cmd(as_json: bool, fail_on: str | None) -> None:
    """Answer 'what is this agent already allowed to call?' before 'is that repo safe?'.

    Configs are read as text and parsed as JSON. No server is launched and no
    remote URL is contacted — discovery stays inside the same static-only
    guarantee as an audit.
    """
    from .discovery import discover, to_tools
    from .rules import load_signatures, run_rules
    from .updater import effective_signatures_path

    err = Console(stderr=True)
    servers, texts = discover()
    signatures = load_signatures(effective_signatures_path(None))
    findings = run_rules(to_tools(servers), signatures, has_auth_signal=True, files=texts)
    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), f.id, f.tool_name or ""))

    if as_json:
        click.echo(json.dumps(
            {
                "servers": [s.to_dict() for s in servers],
                "configs_scanned": sorted(texts),
                "findings": [f.to_dict() for f in findings],
                "signature_version": signatures.get("version"),
            },
            indent=2,
        ))
    elif not servers:
        err.print("[yellow]No MCP client configs with registered servers found.[/yellow]")
    else:
        table = Table(title=f"Registered MCP servers ({len(servers)})")
        for column in ("Client", "Server", "Transport", "Launch / URL", "Env keys"):
            table.add_column(column, overflow="fold")
        for s in servers:
            table.add_row(s.client, s.name, s.transport, s.launch or s.url, ", ".join(s.env_keys))
        Console().print(table)
        for f in findings:
            if not f.suppressed:
                Console().print(f"  [red]{f.severity:8}[/red] {f.id:8} {f.tool_name or '-':22} {f.evidence}")

    if fail_on and _at_or_above(findings, fail_on.lower()):
        raise SystemExit(1)
    raise SystemExit(0)


def _verify_against_source(target: str, rows, *, skip: bool, err: Console):
    """Check a docs-derived tool list against the page it was transcribed from.

    Returns None when the target is not such a list. A repo, or a tools/list
    response captured from the running server, is already first-hand evidence —
    stamping it with a provenance column would add a column of noise.
    """
    from .provenance import Provenance, declared_source, verify

    path = Path(target)
    try:
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    source = declared_source(text)
    if not source:
        return None
    if skip:
        return Provenance(source=source, status="skipped")

    prov = verify(sorted({row.action for row in rows}), source)
    if prov.status == "unreachable":
        err.print(f"[yellow]could not verify:[/yellow] {prov.summary()}")
    elif prov.missing:
        err.print(f"[red]{len(prov.missing)} operation(s) not found on the source page:[/red]")
        for missing in prov.missing[:10]:
            err.print(f"  · {missing}")
        if len(prov.missing) > 10:
            err.print(f"  … and {len(prov.missing) - 10} more")
        err.print(
            "[yellow]Those rows are marked NOT ON PAGE.[/yellow] Confirm them against the "
            "vendor's page before this matrix goes to a review board."
        )
    else:
        err.print(f"[green]verified:[/green] {prov.summary()}")
    return prov


@main.command(
    name="matrix",
    help="Build a connector approval matrix (one row per operation) for InfoSec review.",
)
@click.argument("target")
@click.option("--out", "out_path", default="connectors_matrix.xlsx", show_default=True,
              help="Output file. Extension picks the format unless --format is given.")
@click.option("--format", "fmt", type=click.Choice(["xlsx", "csv"], case_sensitive=False),
              default=None, help="Override the format inferred from --out.")
@click.option("--connector", default=None,
              help="Connector name for column A (default: the target's basename).")
@click.option("--platform", default="",
              help="Adds a platform column naming the client(s) this is opened to.")
@click.option("--status", default="Pending InfoSec review", show_default=True,
              help="Constant for the InfoSec status column.")
@click.option("--types", "types_path", type=click.Path(exists=True), default=None,
              help="YAML overrides mapping actions to connector-specific type labels.")
@click.option("--no-prefill", is_flag=True,
              help="Leave the recommendation and status columns empty for a human to fill.")
@click.option("--no-verify", is_flag=True,
              help="Skip checking a docs-derived tool list against its _source page (offline use).")
def matrix_cmd(target: str, out_path: str, fmt: str | None, connector: str | None,
               platform: str, status: str, types_path: str | None, no_prefill: bool,
               no_verify: bool) -> None:
    """Enumerate a connector's operations and classify each one.

    Operations come from whatever the extractor can already read — a saved
    `tools/list` response, a JSON manifest, or a server's source. The connector
    is never started, so a hosted server needs its tool list supplied as JSON.

    When that JSON names the page it was transcribed from in `_source`, every
    operation is checked against that page and the result travels in a `source`
    column, so a name a model invented reaches the review board labelled rather
    than indistinguishable from the real ones.
    """
    from .matrix import Overrides, apply_provenance, build_matrix, summarize, write_csv, write_xlsx

    err = Console(stderr=True)
    try:
        report, tools = audit_detailed(target)
    except FileNotFoundError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2)
    except Exception as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2)

    if not tools:
        err.print(
            "[yellow]No operations found.[/yellow] For a hosted connector with no source, "
            "save its tools/list response as JSON and pass that file instead."
        )
        raise SystemExit(2)

    name = connector or Path(target).name or target
    rows = build_matrix(tools, name, status=status, platform=platform,
                        overrides=Overrides.load(types_path), prefill=not no_prefill)

    prov = _verify_against_source(target, rows, skip=no_verify, err=err)
    if prov is not None:
        apply_provenance(rows, prov)

    chosen = (fmt or Path(out_path).suffix.lstrip(".") or "xlsx").lower()
    try:
        if chosen == "csv":
            write_csv(rows, out_path, platform=bool(platform))
        else:
            write_xlsx(rows, out_path, platform=bool(platform))
    except RuntimeError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2)

    table = Table(title=f"{name} — {len(rows)} operations")
    table.add_column("type")
    table.add_column("count", justify="right")
    for type_label, count in summarize(rows).items():
        table.add_row(type_label, str(count))
    Console(stderr=True).print(table)
    err.print(f"[green]Matrix written[/green] -> {out_path}")
    err.print("Columns A-D are generated; fill in the recommendation, status and comments.")
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
@click.option("--no-blogs", is_flag=True, help="Skip the researcher-blog RSS source.")
@click.option("--no-hn", is_flag=True, help="Skip the Hacker News source.")
@click.option(
    "--min-tier",
    type=click.Choice(["top", "ranked", "community", "preprint"], case_sensitive=False),
    default="preprint",
    show_default=True,
    help="Quality floor: 'top' = Big-4 security venues / Q1 journals / top ML venues; "
         "'ranked' adds other peer-reviewed venues; 'community' adds researcher blogs and "
         "Hacker News; 'preprint' keeps everything. CVE advisories always pass.",
)
def intel_fetch(
    queue_path: str | None,
    max_results: int,
    no_arxiv: bool,
    no_cve: bool,
    no_blogs: bool,
    no_hn: bool,
    min_tier: str,
) -> None:
    from .intel import advisories, arxiv, feeds, hackernews
    from .intel import queue as q
    from .intel.model import filter_by_min_tier

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
    if not no_blogs:
        try:
            fetched += feeds.fetch()
        except Exception as exc:
            err.print(f"[yellow]blog-feed fetch failed:[/yellow] {exc}")
    if not no_hn:
        try:
            fetched += hackernews.fetch()
        except Exception as exc:
            err.print(f"[yellow]hn fetch failed:[/yellow] {exc}")

    kept = filter_by_min_tier(fetched, min_tier.lower())
    dropped = len(fetched) - len(kept)
    new = q.add_candidates(path, kept)
    note = f", {dropped} below --min-tier {min_tier.lower()}" if dropped else ""
    err.print(
        f"[green]{len(new)} new candidate(s)[/green] queued at {path} "
        f"({len(fetched)} fetched{note}, deduped against the Atlas)."
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

    from .intel.model import TIER_ORDER

    _TIER_STYLE = {
        "advisory": "bold red",
        "top": "bold green",
        "ranked": "cyan",
        "community": "yellow",
        "preprint": "dim",
    }
    items.sort(key=lambda c: (TIER_ORDER.get(c.tier, 9), c.published), reverse=False)

    table = Table(show_lines=True, title="MCP intel review queue (best sources first)")
    table.add_column("Tier", no_wrap=True)
    table.add_column("Venue", no_wrap=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Id", no_wrap=True)
    table.add_column("Title")
    table.add_column("Matched", no_wrap=True)
    for c in items:
        tier = c.tier or "preprint"
        table.add_row(
            f"[{_TIER_STYLE.get(tier, '')}]{tier}[/]",
            c.venue or "—",
            c.source,
            c.ident or "—",
            c.title,
            ", ".join(c.matched[:3]),
        )
    console.print(table)
    console.print(f"[dim]{len(items)} item(s). Curate by hand into signatures.yaml + threats.yaml.[/dim]")
    raise SystemExit(0)


@intel_group.command(
    name="curate",
    help="Fast, LLM-free interactive curation: review one queued candidate at a "
         "time, type a name, hit y — it's merged into threats.yaml immediately. "
         "No API key needed; use this while --use-llm isn't worth the cost.",
)
@click.option("--queue", "queue_path", default=None, help="Review-queue JSONL path.")
@click.option("--atlas", "atlas_path", type=click.Path(exists=True), default=None,
              help="threats.yaml to merge into (default: the bundled one).")
@click.option("--limit", type=int, default=None, help="Stop after reviewing this many candidates.")
def intel_curate(queue_path: str | None, atlas_path: str | None, limit: int | None) -> None:
    from .intel import queue as q
    from .intel.autodraft import build_human_draft, merge_into_atlas
    from .intel.model import TIER_ORDER

    console = Console()
    path = queue_path or _default_queue_path()
    items = q.load_queue(path)
    if not items:
        console.print("[dim]Review queue is empty. Run `mcp-audit intel fetch` first.[/dim]")
        raise SystemExit(0)
    items.sort(key=lambda c: (TIER_ORDER.get(c.tier, 9), c.published), reverse=False)

    decided: set[str] = set()
    drafts: list[dict] = []
    reviewed = 0
    try:
        for cand in items:
            if limit and reviewed >= limit:
                break
            reviewed += 1
            console.rule(f"[{cand.tier or 'preprint'}] {cand.source} В· {cand.venue or '—'}")
            console.print(f"[bold]{cand.title}[/bold]")
            if cand.url:
                console.print(f"[dim]{cand.url}[/dim]")
            if cand.summary:
                console.print(cand.summary[:400])
            if cand.matched:
                console.print(f"[dim]matched: {', '.join(cand.matched)}[/dim]")

            if not click.confirm("Add to Atlas?", default=False):
                decided.add(cand.ident)
                continue
            decided.add(cand.ident)

            name = click.prompt("Threat name", default=cand.title)
            lifecycle = click.prompt(
                "Lifecycle phase (creation/deployment/operation/maintenance)",
                default="operation",
            )
            signal = click.prompt("One-line static signal (Enter to skip)", default="", show_default=False)
            drafts.append(build_human_draft(cand, name=name, lifecycle=lifecycle, static_signal=signal))
    except click.Abort:
        console.print("\n[dim]Stopped early.[/dim]")

    # Decided candidates (approved or explicitly skipped) leave the queue;
    # anything not reached this run stays for next time.
    remaining = [c for c in items if c.ident not in decided]
    q.save_queue(path, remaining)

    if drafts:
        n = merge_into_atlas(drafts, atlas_path=atlas_path)
        console.print(f"[green]{n} entrie(s) merged[/green] into {atlas_path or 'src/mcp_auditor/threats.yaml'}.")
    else:
        console.print("[dim]Nothing merged.[/dim]")
    console.print(f"[dim]{len(remaining)} candidate(s) left in the queue.[/dim]")
    raise SystemExit(0)


@intel_group.command(name="distill", help="Draft candidate detection patterns from queued abstracts (optional --use-llm).")
@click.option("--queue", "queue_path", default=None, help="Review-queue JSONL path.")
@click.option("--use-llm", is_flag=True, help="Enable LLM drafting (OFF by default; sees abstracts only).")
@click.option("--model", default=None, help="Override the provider's default model.")
def intel_distill(queue_path: str | None, use_llm: bool, model: str | None) -> None:
    from .intel import distill as d
    from .intel import queue as q

    console = Console()
    items = q.load_queue(queue_path or _default_queue_path())
    if not items:
        console.print("[dim]Review queue is empty.[/dim]")
        raise SystemExit(0)
    cache = str(_intel_dir() / "distill-cache")
    for c in items:
        result = d.distill(c, use_llm=use_llm, cache_dir=cache, model=model)
        console.print(f"[bold]{c.ident or c.source}[/bold]  {c.title}")
        console.print_json(data=result)
    raise SystemExit(0)


@intel_group.command(
    name="autodraft",
    help="Auto-draft AND merge Atlas entries from high-tier queued candidates via LLM. "
         "The included/excluded criteria (tier, dedup, keyword match, "
         "'the LLM found something statically detectable') ARE the review — "
         "no human copy/paste step. Entries land in threats.yaml with rules: [] "
         "(no executable matcher yet; that part still needs a human, see --help).",
)
@click.option("--queue", "queue_path", default=None, help="Review-queue JSONL path.")
@click.option("--atlas", "atlas_path", type=click.Path(exists=True), default=None,
              help="threats.yaml to merge into (default: the bundled one).")
@click.option("--log", "log_path", default=None,
              help="Audit-trail log of merged entries (default: ~/.mcp-audit/intel/drafts/threats.draft.yaml).")
@click.option(
    "--min-tier",
    type=click.Choice(["advisory", "top", "ranked"], case_sensitive=False),
    default="ranked",
    show_default=True,
    help="Quality floor for auto-merging. 'community' (blogs/HN) and 'preprint' "
         "(unreviewed arXiv) are ALWAYS excluded, regardless of this flag — those "
         "stay in `mcp-audit intel review` for a human to triage; everything else "
         "is trusted unattended. See intel/autodraft.py for the full criteria.",
)
@click.option("--use-llm", is_flag=True,
              help="Enable LLM drafting (OFF by default; without it every candidate "
                   "is excluded as llm_disabled — nothing is invented or merged for free).")
@click.option("--model", default=None, help="Override the provider's default model.")
@click.option("--dry-run", is_flag=True,
              help="Show what would be merged without touching threats.yaml.")
def intel_autodraft(
    queue_path: str | None,
    atlas_path: str | None,
    log_path: str | None,
    min_tier: str,
    use_llm: bool,
    provider: str | None,
    model: str | None,
    dry_run: bool,
) -> None:
    from .atlas import load_atlas
    from .intel import queue as q
    from .intel.autodraft import autodraft, merge_into_atlas, write_drafts

    console = Console()
    err = Console(stderr=True)
    items = q.load_queue(queue_path or _default_queue_path())
    if not items:
        console.print("[dim]Review queue is empty. Run `mcp-audit intel fetch` first.[/dim]")
        raise SystemExit(0)

    cache = str(_intel_dir() / "distill-cache")
    atlas = load_atlas(atlas_path) if atlas_path else None
    result = autodraft(
        items, min_tier=min_tier.lower(), use_llm=use_llm, cache_dir=cache, atlas=atlas,
        model=model,
    )

    table = Table(show_lines=True, title="Auto-draft results")
    table.add_column("Status", no_wrap=True)
    table.add_column("Ident", no_wrap=True)
    table.add_column("Title")
    table.add_column("Reason / draft name")
    for d in result.included:
        table.add_row("[green]merged[/green]" if not dry_run else "[cyan]would merge[/cyan]",
                       d["source"]["ident"], d["source"]["title"], d["name"])
    for e in result.excluded:
        table.add_row("[yellow]excluded[/yellow]", e["ident"], e["title"], e["reason"])
    console.print(table)

    if not result.included:
        err.print("[dim]No candidates passed the auto-merge criteria this run.[/dim]")
        raise SystemExit(0)

    log = log_path or str(_intel_dir() / "drafts" / "threats.draft.yaml")
    write_drafts(log, result.included)

    if dry_run:
        err.print(f"[cyan]--dry-run:[/cyan] {len(result.included)} entrie(s) would be merged; nothing written.")
        raise SystemExit(0)

    n = merge_into_atlas(result.included, atlas_path=atlas_path)
    err.print(
        f"[green]{n} entrie(s) merged[/green] -> {atlas_path or 'src/mcp_auditor/threats.yaml'} "
        f"(needs_review: true, rules: [] — a human still has to write the detector). "
        f"Audit trail -> {log}."
    )
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
