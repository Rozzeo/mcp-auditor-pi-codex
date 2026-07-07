"""MCP surface for the auditor — the tool that audits the tools.

Exposes the same pure ``audit(target) -> AuditReport`` core over the Model
Context Protocol (stdio), so agents can vet an MCP server *before* connecting
to it. Thin wrapper only: no detection logic lives here (spec §3).

Static-only guarantee holds: the served tools read target files as text and
never execute, import, install, or eval them.

Run directly:

    mcp-audit-server            # console script
    python -m mcp_auditor.mcp_server
"""

from __future__ import annotations

from typing import Any, Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The MCP server surface needs the optional 'mcp' dependency. "
        "Install it with: pip install 'mcp-auditor[mcp]'"
    ) from exc

from .atlas import load_atlas_safe, threats_by_id
from .core import audit
from .rules import load_signatures

mcp = FastMCP(
    "mcp-auditor",
    instructions=(
        "Static security auditor for Model Context Protocol servers. "
        "Audit a local directory, single file, or GitHub repository of an MCP "
        "server without running it; results include a 0-100 score and findings "
        "for tool poisoning and over-privileged tools."
    ),
)


@mcp.tool()
def audit_mcp_server(
    target: str,
    signatures_path: Optional[str] = None,
    suppressions_path: Optional[str] = None,
) -> dict[str, Any]:
    """Statically audit an MCP server and return the full AuditReport.

    Args:
        target: Local directory, single source file, or a github.com URL of the
            MCP server whose source is analyzed. The target is read as text and
            is never executed.
        signatures_path: Optional path to a pinned signatures.yaml, for
            reproducible audits against a known rule version.
        suppressions_path: Optional path to an auditor-side suppression file of
            reviewed false positives. Suppressed findings stay in the report
            flagged suppressed=true with their justification, and are excluded
            from the score and summary. A suppression file found inside the
            target itself is never honored.

    Returns:
        The AuditReport as a JSON object: target, is_mcp_server, tools_analyzed,
        score (0-100, null when the target is not an MCP server), findings
        (each with a confidence field: high, medium, or low), summary counts by
        severity, and generated_at.
    """
    return audit(
        target,
        signatures_path=signatures_path,
        suppressions_path=suppressions_path,
    ).to_dict()


@mcp.tool()
def diff_mcp_server_versions(
    old_target: str,
    new_target: str,
    signatures_path: Optional[str] = None,
    suppressions_path: Optional[str] = None,
) -> dict[str, Any]:
    """Compare two audits of the same MCP server (the rug-pull detector).

    Audit both sides statically and report what changed between versions. A
    side may also be a previously saved audit JSON file (a baseline).

    Args:
        old_target: The older version — local directory, GitHub URL, or a saved
            audit-report JSON file. Never executed.
        new_target: The newer version, same accepted forms.
        signatures_path: Optional pinned signatures.yaml applied to both sides.
        suppressions_path: Optional auditor-side suppression file, both sides.

    Returns:
        Score delta, new_findings (each with severity and recommendation),
        resolved_findings, the tool-surface change list (added / removed /
        changed tools), and rug_pull_signal — true when the tool surface
        changed between versions (MCP-T05), which warrants re-review before
        trusting the update.
    """
    from .diffmode import diff_audits

    return diff_audits(
        old_target,
        new_target,
        signatures_path=signatures_path,
        suppressions_path=suppressions_path,
    )


@mcp.tool()
def list_rules(signatures_path: Optional[str] = None) -> dict[str, Any]:
    """List the detection rules in the active signature set.

    Args:
        signatures_path: Optional path to a pinned signatures.yaml.

    Returns:
        Signature set version, release date, and one entry per rule with its
        id, category, severity, message, and linked threat id when present.
    """
    sigs = load_signatures(signatures_path)
    rules = [
        {
            "id": rule_id,
            "category": rule.get("category"),
            "severity": rule.get("severity"),
            "message": rule.get("message"),
            "threat_id": rule.get("threat_id"),
        }
        for rule_id, rule in sigs.get("rules", {}).items()
    ]
    return {
        "version": sigs.get("version"),
        "released": sigs.get("released"),
        "rules": rules,
    }


@mcp.tool()
def explain_threat(threat_id: str) -> dict[str, Any]:
    """Look up an MCP threat-atlas entry by id (e.g. "MCP-T03").

    Args:
        threat_id: Atlas id of the threat class, as found in a finding's
            threat_id field or in list_threats output.

    Returns:
        The full atlas record: name, aliases, attacker model, lifecycle phase,
        severity, summary, static detectability, detecting rules, and cited
        sources. Contains {"error": ...} when the id is unknown.
    """
    atlas = load_atlas_safe()
    if atlas is None:
        return {"error": "threat atlas unavailable in this installation"}
    threat = threats_by_id(atlas).get(threat_id)
    if threat is None:
        known = sorted(threats_by_id(atlas))
        return {"error": f"unknown threat id {threat_id!r}", "known_ids": known}
    return dict(threat)


@mcp.tool()
def list_threats() -> dict[str, Any]:
    """List all threat classes tracked in the MCP threat atlas.

    Returns:
        Atlas version and one summary entry per threat: id, name, severity,
        phase group, static detectability, and the rule ids that detect it.
    """
    atlas = load_atlas_safe()
    if atlas is None:
        return {"error": "threat atlas unavailable in this installation"}
    threats = [
        {
            "id": t.get("id"),
            "name": t.get("name"),
            "severity": t.get("severity"),
            "phase_group": t.get("phase_group"),
            "static_detectability": t.get("static_detectability"),
            "rules": t.get("rules", []),
        }
        for t in threats_by_id(atlas).values()
    ]
    return {"version": atlas.get("version"), "threats": threats}


def main() -> None:
    """Run the auditor as a stdio MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
