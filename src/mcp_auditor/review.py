"""The review packet (spec §4) - the product's primary output.

A score answers a question nobody asked. What a security specialist actually
needs is a sheet they can sign: what this server exposes, what each tool can do,
which evidence supports every statement, where the sources disagree, what is
still unknown, and what to ask the vendor about it.

Two properties matter more than completeness here.

*The packet never decides.* It records a contextual assessment and leaves the decision,
the reviewer, and the notes empty. An advisory tool that quietly approves things
is a gate wearing a disguise.

*The packet is honest about its own limits.* Coverage sits next to the findings,
every cell carries the kind of evidence behind it, and anything the engine could
not resolve becomes an explicit `UNKNOWN` row and a written question - never an
absence that reads as a clean result.

Nothing is computed here that the engine did not already establish. This module
is a renderer over `AuditReport`, so the CLI, the JSON and any future HTML view
cannot drift into three different answers.
"""

from __future__ import annotations

from typing import Any

from .capabilities import DESTRUCTIVE_CAPABILITIES, MUTATING_CAPABILITIES
from .types import AuditReport, Tool

# Where a statement came from (spec §3). Ordered from weakest to strongest,
# except for the two that describe a problem rather than a source.
EVIDENCE_STATUSES = (
    "CLAIMED",        # documentation only
    "DECLARED",       # MCP metadata, annotations, or schema
    "INFERRED",       # derived statically from source
    "OBSERVED",       # seen in a controlled runtime test
    "VERIFIED",       # accepted by a human reviewer
    "UNKNOWN",        # the available evidence does not answer the question
    "CONTRADICTED",   # two or more evidence sources disagree
)

# The reviewer's vocabulary. The tool proposes; a person picks.
DECISIONS = (
    "APPROVE",
    "APPROVE WITH CONSTRAINTS",
    "NEEDS EVIDENCE",
    "REJECT",
    "RE-REVIEW REQUIRED",
)

ASSESSMENTS = (
    "INSUFFICIENT_EVIDENCE",
    "REJECT_RECOMMENDED",
    "REVIEW_REQUIRED",
    "APPROVE_WITH_CONSTRAINTS",
    "ELIGIBLE_FOR_APPROVAL",
)

# Annotations that claim a tool is harmless, the value that makes the claim,
# and the effects that refute it.
#
# The direction matters and is easy to get backwards: `readOnlyHint: true` says
# the tool changes nothing, while it is `destructiveHint: FALSE` that promises
# no destruction. A tool declaring `destructiveHint: true` and then deleting a
# file is an accurate annotation, not a disagreement, and flagging it would
# punish exactly the servers that document themselves honestly.
_REFUTABLE = {
    "readOnlyHint": (True, MUTATING_CAPABILITIES),
    "destructiveHint": (False, DESTRUCTIVE_CAPABILITIES),
}


def build_packet(report: AuditReport, baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    """Assemble the review packet for one audit."""
    tools = report.tools or []
    contradictions = _contradictions(tools)
    refuted = {(item["tool"], capability) for item in contradictions for capability in item["capabilities"]}

    matrix = _capability_matrix(tools, refuted)
    questions = _questions(report, tools)
    coverage = _coverage(report, tools)

    return {
        "identity": {
            "target": report.target,
            "generated_at": report.generated_at,
            "evidence_type": report.evidence_type,
            "signature_version": report.signature_version,
            "tools_analyzed": report.tools_analyzed,
            "is_mcp_server": report.is_mcp_server,
            "extension_kind": report.extension_kind,
        },
        "coverage": coverage,
        "inventory": [
            {
                "tool": tool.name,
                "location": tool.location,
                "description": tool.description,
                "annotations": tool.annotations or {},
            }
            for tool in sorted(tools, key=lambda item: item.name)
        ],
        "capability_matrix": matrix,
        "contradictions": contradictions,
        "findings": [finding.to_dict() for finding in report.findings if not finding.suppressed],
        "package_inventory": list(report.package_inventory),
        "sensitive_data": list(report.sensitive_data),
        "data_flows": list(report.data_flows),
        "questions": questions,
        "change_report": _change_report(tools, baseline),
        "assessment": _assessment(report, coverage),
        "decision": {
            "status": "PENDING",
            "recommended": _recommend(report, coverage, contradictions, questions),
            "options": list(DECISIONS),
            "reviewer": None,
            "notes": None,
        },
    }


def _capability_matrix(tools: list[Tool], refuted: set[tuple[str, str]]) -> list[dict[str, Any]]:
    """One row per tool/capability, plus an explicit row for each unknown."""
    rows: list[dict[str, Any]] = []
    for tool in sorted(tools, key=lambda item: item.name):
        guard_note = ", ".join(
            f"{guard['name']} ({guard['evidence']})" for guard in tool.guards
        )
        for evidence in tool.capabilities:
            contradicted = (tool.name, evidence.capability) in refuted
            rows.append({
                "tool": tool.name,
                "capability": evidence.capability,
                "evidence_status": "CONTRADICTED" if contradicted else "INFERRED",
                "evidence_reference": evidence.location or tool.location,
                "evidence": evidence.evidence,
                "confidence": evidence.confidence,
                "destructive": evidence.destructive,
                "constraint": guard_note,
                "notes": _contradiction_note(tool, evidence.capability) if contradicted else "",
            })

        # An unresolved handler is not a tool without effects. Say so in the
        # matrix rather than leaving a blank a reader will take for "none".
        if tool.unresolved_calls or tool.external_calls:
            rows.append({
                "tool": tool.name,
                "capability": "*",
                "evidence_status": "UNKNOWN",
                "evidence_reference": tool.location,
                "evidence": "",
                "confidence": "none",
                "destructive": False,
                "constraint": guard_note,
                "notes": "; ".join(tool.unresolved_calls + tool.external_calls),
            })
    return rows


def _contradiction_note(tool: Tool, capability: str) -> str:
    claims = [
        f"{hint}: {str(claimed).lower()}"
        for hint, (claimed, refuting) in _REFUTABLE.items()
        if tool.annotations.get(hint) is claimed and capability in refuting
    ]
    return f"declared {', '.join(claims)}; implementation shows {capability}"


def _contradictions(tools: list[Tool]) -> list[dict[str, Any]]:
    """Where the tool's own annotations disagree with its implementation."""
    out: list[dict[str, Any]] = []
    for tool in sorted(tools, key=lambda item: item.name):
        inferred = {evidence.capability for evidence in tool.capabilities}
        for hint, (claimed, refuting) in _REFUTABLE.items():
            if tool.annotations.get(hint) is not claimed:
                continue
            conflicting = sorted(inferred & refuting)
            if not conflicting:
                continue
            out.append({
                "tool": tool.name,
                "declared": f"{hint}: {str(claimed).lower()}",
                "inferred": ", ".join(conflicting),
                "capabilities": conflicting,
                "location": tool.location,
            })
    return out


def _coverage(report: AuditReport, tools: list[Tool]) -> dict[str, Any]:
    """What the audit did and did not manage to look at."""
    unresolved_registrations = len(report.coverage_gaps or [])
    unresolved_handlers = sorted(
        tool.name for tool in tools if tool.unresolved_calls or tool.external_calls
    )
    package_gaps = list(report.package_coverage_gaps)
    package_files = list(report.package_inventory)
    return {
        "source_roles": report.source_roles or {},
        "unresolved_registrations": unresolved_registrations,
        "unresolved_registration_details": list(report.coverage_gaps or []),
        "unresolved_handlers": unresolved_handlers,
        "package_files_total": len(package_files),
        "package_files_analyzed": sum(bool(item.get("analyzed")) for item in package_files),
        "package_coverage_gaps": package_gaps,
        "complete": not unresolved_registrations and not unresolved_handlers and not package_gaps,
    }


def _reason_kind(note: str) -> str:
    """The class of obstacle a note describes, for grouping the questionnaire."""
    if "outside the repository" in note:
        return "the effect is in an installed package this analysis does not read"
    if "ambiguous" in note:
        return "a helper name resolves to more than one definition in the tree"
    if "dynamic dispatch" in note:
        return "the call target is decided at runtime"
    if "depth limit" in note:
        return "the call chain runs deeper than the analysis follows"
    return note


def _questions(report: AuditReport, tools: list[Tool]) -> list[dict[str, str]]:
    """Turn each unknown into something a vendor can actually answer."""
    questions: list[dict[str, str]] = []
    for gap in report.coverage_gaps or []:
        questions.append({
            "topic": "tool inventory",
            "question": (
                f"A {gap['construct']} call at {gap['location']} could not be resolved "
                f"({gap['reason']}) Which tool does it register, and what does its "
                f"handler do?"
            ),
            "evidence_requested": "the resolved tool name, schema, and handler source",
        })
    # Grouped by reason. A server whose ninety-eight tools all reach the same
    # package raises one question, not ninety-eight copies of it - a
    # questionnaire nobody finishes reading is not evidence gathering. The
    # capability matrix still carries a row per tool, because that is read one
    # tool at a time.
    by_reason: dict[str, list[Tool]] = {}
    examples: dict[str, str] = {}
    for tool in tools:
        notes = tool.unresolved_calls + tool.external_calls
        if not notes:
            continue
        # Grouped by the *kind* of obstacle, not its exact wording. Ninety-eight
        # tools blocked by ninety-eight differently-named ambiguous helpers are
        # one question about ambiguity, not ninety-eight questions.
        kind = "; ".join(sorted({_reason_kind(note) for note in notes}))
        by_reason.setdefault(kind, []).append(tool)
        examples.setdefault(kind, notes[0])

    for reason, affected in by_reason.items():
        reason = f"{reason}; for example {examples[reason]}"
        names = [tool.name for tool in affected]
        if len(affected) == 1:
            subject = f"The handler for '{names[0]}' at {affected[0].location}"
        else:
            listed = ", ".join(names[:5])
            more = f", and {len(names) - 5} more" if len(names) > 5 else ""
            subject = f"The handlers for {len(names)} tools ({listed}{more})"
        questions.append({
            "topic": f"tool: {names[0]}" if len(affected) == 1 else f"{len(names)} tools",
            "tools": names,
            "question": (
                f"{subject} could not be followed to their effects ({reason}). "
                f"What do they read, write, delete, execute, or send externally?"
            ),
            "evidence_requested": "the concrete call targets, or a runtime capture of the tools",
        })
    for gap in report.package_coverage_gaps:
        questions.append({
            "topic": "skill package",
            "question": (
                f"The package reference '{gap.get('reference', '?')}' from "
                f"{gap.get('location', gap.get('skill', '?'))} is unresolved "
                f"({gap.get('reason', 'unknown reason')}). What content or behavior "
                "does it add to the skill?"
            ),
            "evidence_requested": "the exact referenced file from the published package",
        })
    for flow in report.data_flows:
        if flow.get("sink") != "network.external":
            continue
        questions.append({
            "topic": "sensitive data flow",
            "question": (
                f"A possible {flow.get('source')} -> {flow.get('sink')} flow connects "
                f"{flow.get('source_evidence', {}).get('location')} to "
                f"{flow.get('sink_evidence', {}).get('location')}. What exact fields "
                "are transmitted, who controls the destination, and what approval or "
                "redaction constrains the transfer?"
            ),
            "evidence_requested": "data schema, approved destination, minimization, and user-confirmation controls",
        })
    return questions


def _assessment(report: AuditReport, coverage: dict[str, Any]) -> dict[str, Any]:
    """Contextual decision support; deliberately never a universal SAFE claim."""
    active = [finding for finding in report.findings if not finding.suppressed]
    policy_decision = (report.policy or {}).get("decision")
    basis: list[str] = []

    if report.evidence_type in ("documentation", "declared") or not coverage["complete"]:
        verdict = "INSUFFICIENT_EVIDENCE"
        basis.append("analysis coverage or implementation evidence is incomplete")
    elif policy_decision == "deny" or any(
        finding.id == "SP-001"
        or (finding.severity == "critical" and finding.confidence == "high")
        for finding in active
    ):
        verdict = "REJECT_RECOMMENDED"
        basis.append("a high-confidence prohibited condition is present")
    elif report.data_flows or policy_decision == "manual_review" or any(
        finding.severity in ("critical", "high") for finding in active
    ):
        verdict = "REVIEW_REQUIRED"
        basis.append("risk depends on data, destination, permissions, or deployment context")
    elif policy_decision == "allow" and report.policy:
        verdict = "APPROVE_WITH_CONSTRAINTS"
        basis.append("the supplied policy allows the observed capabilities in its stated context")
    else:
        verdict = "ELIGIBLE_FOR_APPROVAL"
        basis.append("no supported prohibited pattern was found in the fully analyzed package")

    return {
        "verdict": verdict,
        "options": list(ASSESSMENTS),
        "universal_safe": False,
        "basis": basis,
        "statement": (
            "This is not a universal safety claim. It is an advisory assessment of "
            "the supplied package, visible evidence, and optional policy context."
        ),
        "limitations": [
            "static analysis does not observe deployed data, identity, or network controls",
            "a possible data flow does not prove that every runtime path transmits data",
        ],
    }


def _change_report(tools: list[Tool], baseline: dict[str, Any] | None) -> dict[str, Any] | None:
    """Inventory and capability differences against a pinned previous review."""
    if baseline is None:
        return None

    previous: dict[str, set[str]] = {}
    for entry in baseline.get("tools") or []:
        previous[entry["name"]] = {
            item["capability"] for item in entry.get("capabilities") or []
        }
    current = {
        tool.name: {evidence.capability for evidence in tool.capabilities} for tool in tools
    }

    changes: list[dict[str, Any]] = []
    for name in sorted(set(previous) & set(current)):
        gained = sorted(current[name] - previous[name])
        lost = sorted(previous[name] - current[name])
        if gained or lost:
            changes.append({"tool": name, "gained": gained, "lost": lost})

    return {
        "baseline_target": baseline.get("target"),
        "baseline_generated_at": baseline.get("generated_at"),
        "added": sorted(set(current) - set(previous)),
        "removed": sorted(set(previous) - set(current)),
        "capability_changes": changes,
    }


def _recommend(
    report: AuditReport,
    coverage: dict[str, Any],
    contradictions: list[dict[str, Any]],
    questions: list[dict[str, str]],
) -> str:
    """Propose a decision. Incompleteness outranks a clean finding list.

    A review of a surface the engine could not fully parse is not an approval
    waiting to happen, so unknowns are asked about before anything else is
    weighed - including when the only evidence is documentation, which can
    never establish what an implementation does.
    """
    if not report.is_mcp_server:
        return "NEEDS EVIDENCE"
    # Documentation says what a vendor claims and declared metadata says what an
    # endpoint advertises; neither establishes what the implementation does.
    # Source and a controlled runtime capture do, so they are not lumped in.
    if report.evidence_type in ("documentation", "declared"):
        return "NEEDS EVIDENCE"
    if questions or not coverage["complete"]:
        return "NEEDS EVIDENCE"
    if contradictions:
        return "RE-REVIEW REQUIRED"
    if any(finding.severity in ("critical", "high") for finding in report.findings
           if not finding.suppressed):
        return "APPROVE WITH CONSTRAINTS"
    return "APPROVE"
