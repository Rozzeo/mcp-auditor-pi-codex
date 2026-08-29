"""The stable data contract (spec §3). Everything in the tool wraps these types.

These shapes are intentionally additive-only across future phases: new fields and
new finding categories may be added, but existing fields must never change meaning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Ordered worst -> least severe. Used for sorting and for --fail-on comparisons.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Original MVP categories plus the research-seeded categories added in v2. The
# list is informational (additive); the scorer/reporter never depend on it.
CATEGORIES = [
    "tool_poisoning",
    "over_privilege",
    "meta",
    "preference_manipulation",
    "name_collision",
    "supply_chain",
    "command_injection",
    "credential_exposure",
    "tool_chaining",
    "data_exfiltration",
    "data_leakage",
    "capability_mismatch",
    "policy_violation",
]


@dataclass(frozen=True)
class CapabilityEvidence:
    """One statically inferred capability with auditable source evidence.

    ``capability`` uses a small, policy-friendly namespace such as
    ``filesystem.read`` or ``network.outbound``.  The evidence is deliberately
    a short source fragment/API name rather than the whole handler body, so it
    can safely travel in JSON reports and departmental approval records.
    """

    capability: str
    evidence: str
    location: str = ""
    confidence: str = "medium"
    destructive: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "capability": self.capability,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "destructive": self.destructive,
        }
        if self.location:
            out["location"] = self.location
        return out


@dataclass
class Tool:
    """A normalized MCP tool definition extracted statically from a target.

    This is the uniform shape every language-specific extractor produces (spec §5).
    """

    name: str
    description: str
    schema: dict[str, Any] = field(default_factory=dict)
    location: str = ""
    # Optional statically-captured function body text (never executed). Used by
    # code-level rules such as CI-001. Empty for manifest/text extractions.
    body: str = ""
    # MCP ToolAnnotations are untrusted behavioral hints.  They are retained so
    # deterministic analysis can compare the claim with the observed handler.
    annotations: dict[str, Any] = field(default_factory=dict)
    # Static capability inference. Populated after extraction, before rules and
    # optional departmental policy evaluation run.
    capabilities: list[CapabilityEvidence] = field(default_factory=list)
    # What the capability walk refused to follow out of this handler: computed
    # dispatch, an ambiguous name, or the depth budget. An explicit unknown,
    # never an implied absence of effects.
    unresolved_calls: list[str] = field(default_factory=list)
    # Verified input guards this handler applies, each naming the function, the
    # kind of parameter it constrains, and the enforcement it was recognized by.
    # Rules read this instead of treating every broad schema as unconstrained.
    guards: list[dict[str, str]] = field(default_factory=list)
    # Extraction bookkeeping: the server object this tool was registered on, so
    # a later pass can apply the namespace it is mounted under. Not serialized -
    # by the time a report is written, `name` is already the wire name.
    registry: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "schema": self.schema,
            "location": self.location,
        }
        if self.body:
            out["body"] = self.body
        if self.annotations:
            out["annotations"] = self.annotations
        if self.capabilities:
            out["capabilities"] = [c.to_dict() for c in self.capabilities]
        if self.unresolved_calls:
            out["unresolved_calls"] = self.unresolved_calls
        if self.guards:
            out["guards"] = self.guards
        return out


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
    # Provenance (added in v2): the Threat Atlas id this finding maps to and the
    # research/CVE sources that justify it. Additive — omitted from to_dict when
    # unset so the original documented shape is preserved for basic findings.
    threat_id: Optional[str] = None
    sources: list[dict[str, Any]] = field(default_factory=list)
    confidence: Optional[str] = None
    # False-positive handling (additive): a suppressed finding stays visible in
    # the report with its justification but is excluded from score and summary.
    suppressed: bool = False
    suppress_reason: Optional[str] = None
    # Human-facing context copied from the versioned Atlas. It teaches why a
    # finding matters, what static evidence proves, and what a reviewer must
    # still establish. Detection remains valid if the Atlas is unavailable.
    education: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "tool_name": self.tool_name,
            "location": self.location,
            "message": self.message,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
        if self.threat_id is not None:
            out["threat_id"] = self.threat_id
        if self.sources:
            out["sources"] = self.sources
        if self.confidence is not None:
            out["confidence"] = self.confidence
        if self.suppressed:
            out["suppressed"] = True
            out["suppress_reason"] = self.suppress_reason
        if self.education:
            out["education"] = self.education
        return out


@dataclass
class AuditReport:
    """The result of `audit(target)` (spec §3)."""

    target: str
    is_mcp_server: bool
    tools_analyzed: int
    score: Optional[int]
    findings: list[Finding]
    generated_at: str
    # Evidence is explicit so a declared docs inventory, static source scan and
    # runtime capture can never be mistaken for equivalent assurance.
    evidence_type: str = "source"
    message: Optional[str] = None
    # The signature-set version this audit ran against (added in v2), so audits
    # are reproducible/pinnable like antivirus definitions. Omitted when unset.
    signature_version: Optional[int] = None
    # The extracted tool surface (added in v3, additive) so a saved --json
    # report works as a full diff baseline (rug-pull detection). Serialized
    # slim — metadata plus inferred capabilities, never the captured body text.
    tools: Optional[list[Tool]] = None
    # Present only when an explicit auditor-side privilege policy was supplied.
    # The target can never provide or auto-enable its own policy.
    policy: Optional[dict[str, Any]] = None
    # Extraction honesty (added in v4, additive). `coverage_gaps` lists tool
    # registrations that were recognized but could not be resolved into a tool;
    # `source_roles` counts the audited files by what they are. A finding count
    # cannot be read as assurance without both.
    coverage_gaps: Optional[list[dict[str, str]]] = None
    source_roles: Optional[dict[str, int]] = None
    # AI-extension package analysis (additive, v5). MCP-only reports leave these
    # empty; skill reviews use them to distinguish a complete package review
    # from a scan of SKILL.md alone.
    extension_kind: str = "mcp"
    package_inventory: list[dict[str, Any]] = field(default_factory=list)
    package_coverage_gaps: list[dict[str, str]] = field(default_factory=list)
    sensitive_data: list[dict[str, Any]] = field(default_factory=list)
    data_flows: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in self.findings:
            if finding.severity in counts and not finding.suppressed:
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
            "evidence_type": self.evidence_type,
        }
        if self.message is not None:
            out["message"] = self.message
        if self.signature_version is not None:
            out["signature_version"] = self.signature_version
        if self.tools is not None:
            out["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "schema": t.schema,
                    "location": t.location,
                    **({"annotations": t.annotations} if t.annotations else {}),
                    **(
                        {"capabilities": [c.to_dict() for c in t.capabilities]}
                        if t.capabilities
                        else {}
                    ),
                }
                for t in self.tools
            ]
        if self.policy is not None:
            out["policy"] = self.policy
        # Omitted when empty so a fully-resolved audit keeps the documented shape.
        if self.coverage_gaps:
            out["coverage_gaps"] = self.coverage_gaps
        if self.source_roles:
            out["source_roles"] = self.source_roles
        if self.extension_kind != "mcp":
            out["extension_kind"] = self.extension_kind
        if self.package_inventory:
            out["package_inventory"] = self.package_inventory
        if self.package_coverage_gaps:
            out["package_coverage_gaps"] = self.package_coverage_gaps
        if self.sensitive_data:
            out["sensitive_data"] = self.sensitive_data
        if self.data_flows:
            out["data_flows"] = self.data_flows
        return out
