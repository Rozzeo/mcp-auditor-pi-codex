"""Diff mode: compare two audits of the same server across versions.

The temporal detector the Atlas marks as a gap for MCP-T05 (rug pulls): a server
that was clean at install time turns malicious in an update. `diff_audits(old,
new)` audits both sides (or loads a saved `--json` report as a baseline) and
reports the score delta, new/resolved findings, and tool-surface changes — an
added tool, or a changed description/schema on an existing tool, is exactly the
rug-pull shape.

Pure computation over `AuditReport`s; no detection logic of its own.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from .core import audit_detailed
from .types import AuditReport, Finding, Tool


def _report_from_dict(data: dict[str, Any]) -> AuditReport:
    """Rebuild an AuditReport from a saved `mcp-audit --json` document."""
    findings = [
        Finding(
            id=f.get("id", "?"),
            category=f.get("category", ""),
            severity=f.get("severity", "info"),
            tool_name=f.get("tool_name"),
            location=f.get("location", ""),
            message=f.get("message", ""),
            evidence=f.get("evidence", ""),
            recommendation=f.get("recommendation", ""),
            threat_id=f.get("threat_id"),
            sources=f.get("sources", []),
            confidence=f.get("confidence"),
            suppressed=bool(f.get("suppressed", False)),
            suppress_reason=f.get("suppress_reason"),
        )
        for f in data.get("findings", [])
        if isinstance(f, dict)
    ]
    return AuditReport(
        target=data.get("target", "?"),
        is_mcp_server=bool(data.get("is_mcp_server", True)),
        tools_analyzed=int(data.get("tools_analyzed", 0)),
        score=data.get("score"),
        findings=findings,
        generated_at=data.get("generated_at", ""),
        message=data.get("message"),
        signature_version=data.get("signature_version"),
    )


def _load_side(
    target: str,
    signatures_path: str | None,
    suppressions_path: str | None,
) -> tuple[AuditReport, Optional[list[Tool]]]:
    """A diff side is either a saved report JSON (baseline) or a live target.

    Returns (report, tools); tools is None for a JSON baseline, which carries
    findings but not the extracted tool surface.
    """
    p = Path(target)
    if p.is_file() and p.suffix.lower() == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError):
            data = None
        if isinstance(data, dict) and "findings" in data and "score" in data:
            tools = None
            if isinstance(data.get("tools"), list):
                tools = [
                    Tool(
                        name=str(t.get("name", "")),
                        description=str(t.get("description", "")),
                        schema=t.get("schema") if isinstance(t.get("schema"), dict) else {},
                        location=str(t.get("location", "")),
                    )
                    for t in data["tools"]
                    if isinstance(t, dict) and t.get("name")
                ]
            return _report_from_dict(data), tools
    report, tools = audit_detailed(target, signatures_path, suppressions_path)
    return report, tools


def _active(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if not f.suppressed]


def _key(f: Finding) -> tuple[str, str]:
    # Locations shift with unrelated edits; rule id + tool is the stable identity.
    return (f.id, f.tool_name or "")


def _take(findings: list[Finding], keys: Counter) -> list[Finding]:
    remaining = Counter(keys)
    out = []
    for f in findings:
        k = _key(f)
        if remaining.get(k, 0) > 0:
            remaining[k] -= 1
            out.append(f)
    return out


def _diff_tools(old: list[Tool], new: list[Tool]) -> dict[str, Any]:
    old_by = {t.name: t for t in old}
    new_by = {t.name: t for t in new}
    added = sorted(set(new_by) - set(old_by))
    removed = sorted(set(old_by) - set(new_by))
    changed = []
    for name in sorted(set(old_by) & set(new_by)):
        o, n = old_by[name], new_by[name]
        changes = []
        if o.description.strip() != n.description.strip():
            changes.append("description")
        if o.schema != n.schema:
            changes.append("schema")
        if changes:
            changed.append({"name": name, "changes": changes})
    return {"added": added, "removed": removed, "changed": changed}


def diff_audits(
    old_target: str,
    new_target: str,
    signatures_path: str | None = None,
    suppressions_path: str | None = None,
) -> dict[str, Any]:
    """Audit (or load) both sides and return the structured diff."""
    old_report, old_tools = _load_side(old_target, signatures_path, suppressions_path)
    new_report, new_tools = _load_side(new_target, signatures_path, suppressions_path)

    old_active = _active(old_report.findings)
    new_active = _active(new_report.findings)
    oc, nc = Counter(map(_key, old_active)), Counter(map(_key, new_active))
    new_findings = _take(new_active, nc - oc)
    resolved = _take(old_active, oc - nc)

    tools = (
        _diff_tools(old_tools, new_tools)
        if old_tools is not None and new_tools is not None
        else None
    )
    rug_pull = bool(tools and (tools["added"] or tools["changed"]))

    score_delta = None
    if old_report.score is not None and new_report.score is not None:
        score_delta = new_report.score - old_report.score

    def side(r: AuditReport) -> dict[str, Any]:
        return {
            "target": r.target,
            "score": r.score,
            "tools_analyzed": r.tools_analyzed,
            "generated_at": r.generated_at,
            "signature_version": r.signature_version,
        }

    return {
        "old": side(old_report),
        "new": side(new_report),
        "score_delta": score_delta,
        "new_findings": [f.to_dict() for f in new_findings],
        "resolved_findings": [f.to_dict() for f in resolved],
        # None when a side is a JSON baseline (no tool surface to compare).
        "tools": tools,
        # Rug-pull signal (MCP-T05): the tool surface changed between versions.
        "rug_pull_signal": rug_pull,
    }
