"""The single pure entry point: `audit(target) -> AuditReport` (spec §3).

All logic lives behind this function; every surface (CLI, JSON, future web/PDF)
is a thin wrapper around it. The function never executes target code.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .atlas import load_atlas_safe, resolve_sources
from .capabilities import infer_all
from .extractor import extract
from .loader import load_local
from .rules import load_signatures, run_rules
from .scorer import score_findings
from .types import AuditReport
from .updater import effective_atlas_path, effective_signatures_path

_GITHUB_URL = re.compile(r"^https?://(www\.)?github\.com/", re.IGNORECASE)

# Heuristic signals that the server performs some authentication (for ME-001).
_AUTH_SIGNALS = re.compile(
    r"\b(authorization|bearer|oauth|api[_-]?key|authenticate|auth_token|"
    r"require_auth|verify_token|access_token|x-api-key|TokenVerifier|"
    r"BearerAuth|AuthSettings|auth\s*=)\b",
    re.IGNORECASE,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detect_auth_signal(files: dict[str, str]) -> bool:
    for text in files.values():
        if _AUTH_SIGNALS.search(text):
            return True
    return False


def audit(
    target: str,
    signatures_path: str | None = None,
    suppressions_path: str | None = None,
    policy_path: str | None = None,
    employee: str | None = None,
    agent: str | None = None,
) -> AuditReport:
    """Statically audit an MCP server target (local path or GitHub URL).

    ``suppressions_path`` is an auditor-supplied false-positive list (see
    suppressions.py). It is never read from inside the target — a server must
    not be able to vouch for itself.
    """
    report, _tools = audit_detailed(
        target,
        signatures_path,
        suppressions_path,
        policy_path,
        employee,
        agent,
    )
    return report


def audit_detailed(
    target: str,
    signatures_path: str | None = None,
    suppressions_path: str | None = None,
    policy_path: str | None = None,
    employee: str | None = None,
    agent: str | None = None,
):
    """`audit()` plus the extracted tool list — used by diff mode to compare
    tool surfaces across versions. Same static-only guarantee."""
    if _GITHUB_URL.match(target):
        from .fetcher import fetch_github  # imported lazily; network optional

        files = fetch_github(target)
    else:
        files = load_local(target)

    extraction = extract(files)
    infer_all(extraction.tools)
    generated_at = _now_iso()

    if not extraction.is_mcp_server:
        return (
            AuditReport(
                target=target,
                is_mcp_server=False,
                tools_analyzed=0,
                score=None,
                findings=[],
                generated_at=generated_at,
                message=(
                    "No MCP tool definitions or MCP SDK dependency found. "
                    "This does not appear to be an MCP server; no score was computed."
                ),
            ),
            [],
        )

    # Prefer the updated definition cache (mcp-audit update) over the bundled
    # set, unless an explicit --signatures path was given.
    signatures = load_signatures(effective_signatures_path(signatures_path))
    has_auth = _detect_auth_signal(files)
    findings = run_rules(extraction.tools, signatures, has_auth_signal=has_auth, files=files)
    policy_report = None
    if policy_path:
        from .policy import evaluate_policy, load_policy, resolve_policy

        policy = load_policy(policy_path)
        resolved = resolve_policy(policy, employee=employee, agent=agent)
        policy_findings, policy_report = evaluate_policy(
            extraction.tools,
            resolved,
            signatures["rules"]["PV-001"],
        )
        findings.extend(policy_findings)
    elif employee is not None or agent is not None:
        raise ValueError("--employee/--agent require an explicit --policy file")

    # Enrich each finding with the research/CVE citations from the Threat Atlas.
    # Best-effort: if the Atlas is missing, detection still stands, just uncited.
    atlas = load_atlas_safe(effective_atlas_path())
    if atlas:
        for finding in findings:
            sources = resolve_sources(atlas, finding.threat_id)
            if sources:
                finding.sources = sources

    if suppressions_path:
        from .suppressions import apply_suppressions, load_suppressions

        apply_suppressions(findings, load_suppressions(suppressions_path))

    findings.sort(key=_finding_sort_key)
    score = score_findings(findings)

    return (
        AuditReport(
            target=target,
            is_mcp_server=True,
            tools_analyzed=len(extraction.tools),
            score=score,
            findings=findings,
            generated_at=generated_at,
            signature_version=signatures.get("version"),
            tools=extraction.tools,
            policy=policy_report,
        ),
        extraction.tools,
    )


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding_sort_key(finding):
    return (_SEVERITY_RANK.get(finding.severity, 9), finding.id, finding.tool_name or "")
