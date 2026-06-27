"""Command-line surface (spec §8).

    mcp-audit <github-url | path> [--json] [--fail-on <severity>]

Thin wrapper over `audit()`. In `--json` mode, stdout carries ONLY the
`AuditReport` JSON; all progress/errors go to stderr so the output pipes cleanly.
"""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console

from .core import audit
from .reporter import render_human
from .types import SEVERITY_ORDER

_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def _at_or_above(findings, threshold: str) -> bool:
    limit = _SEVERITY_RANK[threshold]
    return any(_SEVERITY_RANK.get(f.severity, 99) <= limit for f in findings)


@click.command(
    name="mcp-audit",
    help="Statically audit an MCP server for tool poisoning and over-privileged tools.",
)
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, help="Emit the AuditReport as JSON on stdout (and nothing else).")
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER, case_sensitive=False),
    default=None,
    help="Exit non-zero if any finding at or above this severity exists (for CI gating).",
)
@click.option("--signatures", "signatures_path", type=click.Path(exists=True), default=None,
              help="Path to a custom signatures.yaml.")
def main(target: str, as_json: bool, fail_on: str | None, signatures_path: str | None) -> None:
    # All human/progress output goes to stderr so --json keeps stdout clean.
    err = Console(stderr=True)

    try:
        report = audit(target, signatures_path=signatures_path)
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

    if fail_on:
        if report.is_mcp_server and _at_or_above(report.findings, fail_on.lower()):
            raise SystemExit(1)

    raise SystemExit(0)


if __name__ == "__main__":
    main()
