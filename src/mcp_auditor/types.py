"""The stable data contract (spec §3). Everything in the tool wraps these types.

These shapes are intentionally additive-only across future phases: new fields and
new finding categories may be added, but existing fields must never change meaning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Ordered worst -> least severe. Used for sorting and for --fail-on comparisons.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

CATEGORIES = ["tool_poisoning", "over_privilege", "meta"]


@dataclass
class Tool:
    """A normalized MCP tool definition extracted statically from a target.

    This is the uniform shape every language-specific extractor produces (spec §5).
    """

    name: str
    description: str
    schema: dict[str, Any] = field(default_factory=dict)
    location: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "schema": self.schema,
            "location": self.location,
        }


@dataclass
class Finding:
    """A single explainable detection (spec §3)."""

    id: str
    category: str
    severity: str
    tool_name: Optional[str]
    location: str
    message: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "tool_name": self.tool_name,
            "location": self.location,
            "message": self.message,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class AuditReport:
    """The result of `audit(target)` (spec §3)."""

    target: str
    is_mcp_server: bool
    tools_analyzed: int
    score: Optional[int]
    findings: list[Finding]
    generated_at: str
    message: Optional[str] = None

    def summary(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "target": self.target,
            "is_mcp_server": self.is_mcp_server,
            "tools_analyzed": self.tools_analyzed,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
            "generated_at": self.generated_at,
        }
        if self.message is not None:
            out["message"] = self.message
        return out
