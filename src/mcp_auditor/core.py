"""The single pure entry point: `audit(target) -> AuditReport` (spec §3).

All logic lives behind this function; every surface (CLI, JSON, future web/PDF)
is a thin wrapper around it. The function never executes target code.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .extractor import extract
from .loader import load_local
from .rules import load_signatures, run_rules
from .scorer import score_findings
from .types import AuditReport

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


def audit(target: str, signatures_path: str | None = None) -> AuditReport:
    """Statically audit an MCP server target (local path or GitHub URL)."""
    if _GITHUB_URL.match(target):
        from .fetcher import fetch_github  # imported lazily; network optional

        files = fetch_github(target)
    else:
        files = load_local(target)

    extraction = extract(files)
    generated_at = _now_iso()

    if not extraction.is_mcp_server:
        return AuditReport(
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
        )

    signatures = load_signatures(signatures_path)
    has_auth = _detect_auth_signal(files)
    findings = run_rules(extraction.tools, signatures, has_auth_signal=has_auth)
    findings.sort(key=_finding_sort_key)
    score = score_findings(findings)

    return AuditReport(
        target=target,
        is_mcp_server=True,
        tools_analyzed=len(extraction.tools),
        score=score,
        findings=findings,
        generated_at=generated_at,
    )


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding_sort_key(finding):
    return (_SEVERITY_RANK.get(finding.severity, 9), finding.id, finding.tool_name or "")
