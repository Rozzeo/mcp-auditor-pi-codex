"""Evidence-backed analysis of complete Codex/Claude skill packages.

The extractor normalizes a SKILL.md into a Tool so the existing threat rules can
inspect its instructions. This module keeps the package boundary intact: files,
references, opaque assets, sensitive-data sources, sinks, and possible flows.
Nothing from the target is imported or executed.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import PurePosixPath
from typing import Any

from .types import Finding


_SCRIPT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".ps1"}
_REFERENCE_EXT = {".md", ".mdx", ".rst", ".txt", ".csv", ".xml", ".html", ".sql"}
_CONFIG_EXT = {".json", ".yaml", ".yml", ".toml", ".lock", ".cfg", ".ini"}

_MARKDOWN_REF = re.compile(r"\]\((?!https?://|mailto:|#)([^)#?]+)", re.IGNORECASE)
_CODE_REF = re.compile(
    r"`((?:scripts?|references?|assets?|templates?)/[^`\s]+|[^`\s/]+\.(?:py|js|ts|sh|ps1|md|txt|csv|pdf))`",
    re.IGNORECASE,
)
_HOST = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
_URL = re.compile(rf"https?://({_HOST})(?::\d+)?(?:[/\s'\"`.,)]|$)", re.IGNORECASE)
_SEND = re.compile(
    r"requests\.(?:post|put|patch)|httpx\.(?:post|put|patch)|axios(?:\.(?:post|put|patch))?\s*\(|"
    r"fetch\s*\(|curl\b|Invoke-WebRequest|webhook",
    re.IGNORECASE,
)
_PROCESS = re.compile(
    r"\b(?:os\.system|subprocess\.|child_process|execFile|execSync|spawn\s*\(|shell\s*=\s*True|"
    r"bash\s+-c|sh\s+-c|powershell)\b",
    re.IGNORECASE,
)
_LOG = re.compile(r"\b(?:print|console\.log|logger\.(?:info|debug|warning|error))\s*\(", re.IGNORECASE)
_WRITE = re.compile(
    r"\b(?:writeFile|write_text|write_bytes|appendFile|createWriteStream|open\s*\([^\n,]+,\s*['\"][wax])",
    re.IGNORECASE,
)

_SOURCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pii.employee", re.compile(r"\b(?:employee|employees|staff|workforce|human resources|hr records?|payroll|salary)\b", re.I)),
    ("pii.customer", re.compile(r"\b(?:customer|customers|client|clients|crm|contacts?|account holders?)\b", re.I)),
    ("pii.health", re.compile(r"\b(?:patient|patients|medical records?|health records?|diagnos(?:is|es))\b", re.I)),
    ("pii.financial", re.compile(r"\b(?:bank account|credit card|payment records?|iban|financial records?)\b", re.I)),
    ("company.files", re.compile(r"\b(?:workspace|source code|internal documents?|company files?|project files?|repository files?)\b", re.I)),
    ("credentials", re.compile(r"\b(?:credentials?|api keys?|access tokens?|passwords?|secrets?|environment variables?)\b", re.I)),
)

_EMAIL = re.compile(rf"(?<![\w.+-])([A-Z0-9._%+-]+)@({_HOST})(?![\w-])", re.I)
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "example.dev", "test.invalid", "corp.invalid"}


def _norm(path: str) -> str:
    return posixpath.normpath(path.replace("\\", "/")).lstrip("./")


def _role(path: str) -> str:
    name = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(path).suffix.lower()
    if name == "skill.md":
        return "instruction"
    if suffix in _SCRIPT_EXT:
        return "script"
    if suffix in _REFERENCE_EXT:
        return "reference"
    if suffix in _CONFIG_EXT:
        return "config"
    return "asset"


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _observation(
    direction: str,
    category: str,
    path: str,
    text: str,
    match: re.Match[str],
    evidence: str,
    confidence: str,
) -> dict[str, Any]:
    return {
        "direction": direction,
        "category": category,
        "evidence": evidence,
        "location": f"{path}:{_line(text, match.start())}",
        "confidence": confidence,
    }


def _references(path: str, text: str) -> set[str]:
    base = posixpath.dirname(path)
    refs = {match.group(1).strip().strip("<>") for match in _MARKDOWN_REF.finditer(text)}
    refs.update(match.group(1).strip() for match in _CODE_REF.finditer(text))
    resolved = set()
    for value in refs:
        value = value.rstrip(".,;:")
        if not value or value.startswith(("http://", "https://", "mailto:", "#")):
            continue
        resolved.add(_norm(posixpath.join(base, value)))
    return resolved


def _package_root(skill_path: str) -> str:
    return posixpath.dirname(skill_path)


def _belongs(path: str, root: str, roots: list[str]) -> bool:
    candidates = [item for item in roots if not item or path == item or path.startswith(item + "/")]
    return bool(candidates) and max(candidates, key=len) == root


def analyze_skill_packages(
    files: dict[str, str],
    signatures: dict[str, Any],
    raw_inventory: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return package evidence and findings for every discovered SKILL.md."""
    normalized_files = {_norm(path): text for path, text in files.items()}
    skill_paths = sorted(path for path in normalized_files if PurePosixPath(path).name.lower() == "skill.md")
    if not skill_paths:
        return {
            "extension_kind": "mcp",
            "inventory": [],
            "coverage_gaps": [],
            "observations": [],
            "flows": [],
            "findings": [],
        }

    inventory_input = raw_inventory or [
        {"path": path, "size": len(text.encode("utf-8")), "analyzed": True}
        for path, text in normalized_files.items()
    ]
    raw_by_path = {_norm(str(item["path"])): dict(item) for item in inventory_input}
    roots = sorted({_package_root(path) for path in skill_paths}, key=len)

    inventory: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    observations: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    findings: list[Finding] = []

    for skill_path in skill_paths:
        root = _package_root(skill_path)
        package_paths = sorted(path for path in raw_by_path if _belongs(path, root, roots))
        skill_text = normalized_files[skill_path]
        refs = _references(skill_path, skill_text)
        referenced_by: dict[str, list[str]] = {ref: [skill_path] for ref in refs}

        for ref in sorted(refs):
            if ref not in raw_by_path:
                gaps.append({
                    "skill": skill_path,
                    "reference": ref,
                    "location": skill_path,
                    "reason": "missing reference",
                })
            elif ref not in normalized_files:
                gaps.append({
                    "skill": skill_path,
                    "reference": ref,
                    "location": ref,
                    "reason": "referenced file was inventoried but not analyzed",
                })

        for path in package_paths:
            raw = raw_by_path[path]
            role = _role(path)
            analyzed = path in normalized_files and bool(raw.get("analyzed", True))
            required = role in {"instruction", "script"} or path in referenced_by
            if role == "script" and not analyzed:
                gaps.append({
                    "skill": skill_path,
                    "reference": path,
                    "location": path,
                    "reason": "executable package file was not analyzed",
                })
            inventory.append({
                "skill": skill_path,
                "path": path,
                "role": role,
                "size": int(raw.get("size", 0)),
                "analyzed": analyzed,
                "required_for_review": required,
                "referenced_by": referenced_by.get(path, []),
            })

        package_texts = {
            path: normalized_files[path]
            for path in package_paths
            if path in normalized_files
        }
        package_observations: list[dict[str, Any]] = []
        literal_sensitive: list[dict[str, Any]] = []
        for path, text in package_texts.items():
            for category, pattern in _SOURCE_PATTERNS:
                match = pattern.search(text)
                if match:
                    package_observations.append(_observation(
                        "source", category, path, text, match,
                        f"instruction/source text references {match.group(0)!r}", "medium",
                    ))

            for match in _EMAIL.finditer(text):
                domain = match.group(2).lower()
                if domain in _PLACEHOLDER_DOMAINS or domain.endswith(".invalid"):
                    continue
                item = _observation(
                    "source", "pii.email", path, text, match,
                    "email address embedded in package (value redacted)", "high",
                )
                package_observations.append(item)
                literal_sensitive.append(item)
            for match in _SSN.finditer(text):
                item = _observation(
                    "source", "pii.government_id", path, text, match,
                    "government identifier embedded in package (value redacted)", "high",
                )
                package_observations.append(item)
                literal_sensitive.append(item)

            url = _URL.search(text)
            send = _SEND.search(text)
            if url or send:
                match = send or url
                assert match is not None
                host = url.group(1) if url else "dynamic destination"
                confidence = "high" if send and url else "medium"
                package_observations.append(_observation(
                    "sink", "network.external", path, text, match,
                    f"outbound destination/call: {host}", confidence,
                ))
            for category, pattern, evidence in (
                ("process.execute", _PROCESS, "process or shell execution"),
                ("logs", _LOG, "data may be written to logs"),
                ("filesystem.write", _WRITE, "data may be written to a file"),
            ):
                match = pattern.search(text)
                if match:
                    package_observations.append(_observation(
                        "sink", category, path, text, match, evidence, "medium",
                    ))

        observations.extend(package_observations)
        sources = [item for item in package_observations if item["direction"] == "source"]
        sinks = [item for item in package_observations if item["direction"] == "sink"]
        # A concrete API call in a referenced script is stronger evidence than
        # a destination merely mentioned in SKILL.md, so present it first.
        sinks.sort(
            key=lambda item: (
                item["confidence"] == "high",
                item["location"].rsplit(":", 1)[0] != skill_path,
            ),
            reverse=True,
        )
        referenced = set(refs)
        package_flows: dict[tuple[str, str], dict[str, Any]] = {}
        for source in sources:
            source_path = source["location"].rsplit(":", 1)[0]
            for sink in sinks:
                sink_path = sink["location"].rsplit(":", 1)[0]
                connected = source_path == sink_path or sink_path in referenced
                if not connected:
                    continue
                candidate = {
                    "skill": skill_path,
                    "source": source["category"],
                    "sink": sink["category"],
                    "status": "POSSIBLE",
                    "confidence": "medium" if sink["confidence"] == "high" else "low",
                    "source_evidence": source,
                    "sink_evidence": sink,
                    "constraints": [],
                }
                key = (source["category"], sink["category"])
                # One reviewer question per semantic route. If the instructions
                # mention a URL and a referenced script contains the actual API
                # call, retain the concrete script evidence instead of emitting
                # two copies of the same possible flow.
                current = package_flows.get(key)
                if current is None or _flow_strength(
                    candidate, skill_path
                ) > _flow_strength(current, skill_path):
                    package_flows[key] = candidate

        flows.extend(package_flows.values())

        if literal_sensitive:
            rule = signatures.get("rules", {}).get("SP-001")
            if rule:
                first = literal_sensitive[0]
                findings.append(_finding(
                    "SP-001", rule, skill_path, first["location"],
                    first["evidence"],
                ))

        network_flows = [
            flow for flow in flows
            if flow["skill"] == skill_path and flow["sink"] == "network.external"
        ]
        if network_flows:
            rule = signatures.get("rules", {}).get("SF-001")
            if rule:
                flow = network_flows[0]
                evidence = (
                    f"{flow['source']} at {flow['source_evidence']['location']} -> "
                    f"{flow['sink']} at {flow['sink_evidence']['location']}"
                )
                findings.append(_finding("SF-001", rule, skill_path, skill_path, evidence))

    kind = "skill" if len(skill_paths) and not any(
        "@modelcontextprotocol/" in text or "FastMCP" in text or "MCPServer" in text
        for text in normalized_files.values()
    ) else "mixed"
    return {
        "extension_kind": kind,
        "inventory": sorted(inventory, key=lambda item: (item["skill"], item["path"])),
        "coverage_gaps": gaps,
        "observations": observations,
        "flows": flows,
        "findings": findings,
    }


def _finding(
    rule_id: str,
    rule: dict[str, Any],
    skill: str,
    location: str,
    evidence: str,
) -> Finding:
    return Finding(
        id=rule_id,
        category=rule["category"],
        severity=rule["severity"],
        tool_name=skill,
        location=location,
        message=rule["message"],
        evidence=evidence,
        recommendation=rule["recommendation"],
        threat_id=rule.get("threat"),
        confidence=rule.get("confidence"),
    )


def _flow_strength(flow: dict[str, Any], skill_path: str) -> tuple[int, int, int]:
    sink = flow["sink_evidence"]
    source = flow["source_evidence"]
    sink_path = sink["location"].rsplit(":", 1)[0]
    return (
        1 if sink["confidence"] == "high" else 0,
        1 if sink_path != skill_path else 0,
        1 if source["confidence"] == "high" else 0,
    )
