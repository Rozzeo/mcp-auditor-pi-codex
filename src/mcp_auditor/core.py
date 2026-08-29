"""The single pure entry point: `audit(target) -> AuditReport` (spec §3).

All logic lives behind this function; every surface (CLI, JSON, future web/PDF)
is a thin wrapper around it. The function never executes target code.
"""

from __future__ import annotations

import re
import json
from datetime import datetime, timezone

from .atlas import load_atlas_safe, resolve_sources, threats_by_id
from .capabilities import infer_all
from .extractor import extract
from .loader import inventory_local, load_local
from .rules import load_signatures, run_rules
from .scorer import score_findings
from .source_roles import role_counts
from .skill_analysis import analyze_skill_packages
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


_ANY_URL = re.compile(r"^\s*https?://", re.IGNORECASE)


def _reject_non_github_url(target: str) -> None:
    """A URL that isn't a GitHub repo is a documentation or product page.

    Falling through to the local loader reported "Target path does not exist",
    which describes neither the problem nor the fix. Reading a vendor page and
    turning prose into a tool list is a model's job — this tool is a
    deterministic parser, and pretending otherwise would put tool names nobody
    can verify into a review artifact.
    """
    if not _ANY_URL.match(target):
        return
    raise ValueError(
        f"{target} is a URL but not a GitHub repository, so there is no source to read. "
        "Documentation and product pages are not parsed: capture the server's tools/list "
        'response as {"tools": [{"name": ..., "description": ...}, ...]} and pass that '
        "file instead. See examples/wpcom-tools.json."
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Package manifests reveal a language even when its source files were filtered
# out by the loader — which is exactly the case that used to be misreported.
_LANGUAGE_MANIFESTS = {
    "composer.json": "PHP",
    "go.mod": "Go",
    "cargo.toml": "Rust",
    "pom.xml": "Java",
    "build.gradle": "Java/Kotlin",
    "gemfile": "Ruby",
}

_UNSCANNED = (
    "It was NOT analyzed, so this is not a clean result. "
    "Statically parsed: Python, TypeScript/JavaScript, WordPress/PHP abilities, "
    "JSON manifests and SKILL.md. "
    "For anything else — or for a hosted server, or one whose tools are registered "
    "dynamically at runtime — capture its tools/list response and audit that JSON."
)


def _not_analyzed_message(files: dict[str, str]) -> str:
    """Say *why* nothing was found, and never imply the target is clean.

    "This does not appear to be an MCP server" is the wrong sentence when the
    real reason is a language the extractor does not read: an unscanned target
    would then read as a passing one, which is the worst failure mode a scanner
    has. Source files in those languages are filtered out before extraction, so
    the language is inferred from the package manifest, which is read.
    """
    found = sorted({
        language for path, language in (
            (p, _LANGUAGE_MANIFESTS.get(p.lower().rsplit("/", 1)[-1])) for p in files
        ) if language
    })
    if found:
        return (
            f"No MCP tool definitions found, and this target looks like a "
            f"{'/'.join(found)} project. " + _UNSCANNED
        )
    return "No MCP tool definitions or MCP SDK dependency found. " + _UNSCANNED


def _detect_auth_signal(files: dict[str, str]) -> bool:
    for text in files.values():
        if _AUTH_SIGNALS.search(text):
            return True
    return False


# Files that can carry an implementation. Prose about a server is not one.
_CODE_EXT = (".py", ".php", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx",
             ".json", ".sh", ".bash", ".zsh", ".ps1", ".toml")


def _evidence_type(files: dict[str, str], skills_detected: bool = False) -> str:
    """Classify what the input proves; never upgrade docs/source to runtime.

    A tree of prose describing an MCP server establishes what the vendor says,
    not what the code does. Labelling that `source` would let a review packet
    inherit an assurance its input cannot support, so it is called what it is.
    An agent skill is the exception: a SKILL.md is the thing that runs, not a
    description of something else that runs.
    """
    declared = False
    for path, text in files.items():
        if not path.lower().endswith(".json"):
            continue
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if str(data.get("capture_kind", "")).endswith("runtime"):
            return "runtime"
        if data.get("_source"):
            declared = True
    if declared:
        return "declared"
    has_code = any(path.lower().endswith(_CODE_EXT) for path in files)
    return "source" if has_code or skills_detected else "documentation"


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
    remote_target = bool(_GITHUB_URL.match(target))
    if remote_target:
        from .fetcher import fetch_github  # imported lazily; network optional

        fetched = fetch_github(target, include_inventory=True)
        # Keep compatibility with integrations that replace the legacy fetcher
        # and return only the text map.
        if isinstance(fetched, tuple):
            files, raw_inventory = fetched
        else:
            files = fetched
            raw_inventory = [
                {"path": path, "size": len(text.encode("utf-8")), "analyzed": True}
                for path, text in files.items()
            ]
    else:
        _reject_non_github_url(target)
        files = load_local(target)
        raw_inventory = inventory_local(target, set(files))

    extraction = extract(files)
    infer_all(extraction.tools, files=files)
    generated_at = _now_iso()
    evidence_type = _evidence_type(files, skills_detected=extraction.skills_detected)

    if not extraction.is_mcp_server:
        return (
            AuditReport(
                target=target,
                is_mcp_server=False,
                tools_analyzed=0,
                score=None,
                findings=[],
                generated_at=generated_at,
                evidence_type=evidence_type,
                message=_not_analyzed_message(files),
                source_roles=role_counts(files),
            ),
            [],
        )

    # Prefer the updated definition cache (mcp-audit update) over the bundled
    # set, unless an explicit --signatures path was given.
    signatures = load_signatures(effective_signatures_path(signatures_path))
    package = analyze_skill_packages(files, signatures, raw_inventory)
    has_auth = _detect_auth_signal(files)
    findings = run_rules(extraction.tools, signatures, has_auth_signal=has_auth, files=files)
    if package["extension_kind"] == "skill":
        # ME-001 is specifically about a network-exposed MCP server. A local
        # Codex/Claude skill has no server authentication boundary, so showing
        # it would teach the reviewer the wrong threat model.
        findings = [finding for finding in findings if finding.id != "ME-001"]
    findings.extend(package["findings"])
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
        atlas_threats = threats_by_id(atlas)
        for finding in findings:
            sources = resolve_sources(atlas, finding.threat_id)
            if sources:
                finding.sources = sources
            threat = atlas_threats.get(finding.threat_id or "")
            if threat:
                finding.education = _education_context(threat)

    if suppressions_path:
        from .suppressions import apply_suppressions, load_suppressions

        apply_suppressions(findings, load_suppressions(suppressions_path))

    findings.sort(key=_finding_sort_key)

    # Coverage and assurance are separate dimensions. A 0-100 number computed
    # over a surface that was only partly parsed reads as assurance the audit
    # cannot support, so an incomplete extraction gets no score at all - and
    # says why, rather than leaving a blank the reader fills in optimistically.
    incomplete = bool(
        extraction.coverage_gaps
        or package["coverage_gaps"]
        or any(tool.unresolved_calls for tool in extraction.tools)
    )
    score = None if incomplete else score_findings(findings)
    message = None
    if incomplete:
        message = (
            "Score withheld: the tool or package surface is incomplete. "
            "Every registration, handler, executable, and referenced package file "
            "must be resolved before a score means anything."
        )

    return (
        AuditReport(
            target=target,
            is_mcp_server=True,
            tools_analyzed=len(extraction.tools),
            score=score,
            findings=findings,
            generated_at=generated_at,
            evidence_type=evidence_type,
            message=message,
            signature_version=signatures.get("version"),
            tools=extraction.tools,
            policy=policy_report,
            coverage_gaps=[gap.to_dict() for gap in extraction.coverage_gaps],
            source_roles=role_counts(files),
            extension_kind=package["extension_kind"],
            package_inventory=package["inventory"],
            package_coverage_gaps=package["coverage_gaps"],
            sensitive_data=package["observations"],
            data_flows=package["flows"],
        ),
        extraction.tools,
    )


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding_sort_key(finding):
    return (_SEVERITY_RANK.get(finding.severity, 9), finding.id, finding.tool_name or "")


def _education_context(threat: dict) -> dict:
    """The decision-support subset of an Atlas entry carried by each finding."""
    keys = (
        "name",
        "summary",
        "scenario",
        "static_detectability",
        "engine_can_establish",
        "engine_cannot_establish",
        "review_questions",
        "safe_example",
        "risky_example",
        "mitigations",
    )
    return {key: threat[key] for key in keys if threat.get(key)}
