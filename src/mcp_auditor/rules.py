"""Rule-based, explainable detection engine (spec §6).

Each rule reads only the statically-extracted tool text/schema and emits zero or
more `Finding`s. Patterns live in `signatures.yaml` so the knowledge base can be
edited without touching code. No LLM calls, no target execution.
"""

from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import yaml

from .types import Finding, Tool

_DEFAULT_SIGNATURES = Path(__file__).with_name("signatures.yaml")

# Codepoints that should never appear in legitimate tool metadata (TP-002).
_HIDDEN_CHARS = {
    "​", "‌", "‍", "﻿",  # zero-width family
    "‪", "‫", "‬", "‭", "‮",  # bidi overrides
    "⁦", "⁧", "⁨", "⁩",  # isolates
}

# Anything that looks like a high-entropy secret, so evidence snippets never leak it.
_SECRET_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{12,}|[A-Za-z0-9_\-]{32,})\b"
)


def load_signatures(path: str | Path | None = None) -> dict[str, Any]:
    """Load the signature set from YAML (defaults to the bundled file)."""
    target = Path(path) if path else _DEFAULT_SIGNATURES
    with open(target, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError(f"Invalid signature file: {target}")
    return data


def run_rules(
    tools: list[Tool],
    signatures: dict[str, Any],
    has_auth_signal: bool,
    files: dict[str, str] | None = None,
) -> list[Finding]:
    """Apply every rule and return all findings.

    Rules operate at three scopes: per-tool (metadata/body), server-level (across
    the whole tool set), and file-level (raw source/config text). `files` is
    optional so older callers and custom signature files keep working; new rules
    are skipped when their key is absent from the signature set.
    """
    rules = signatures["rules"]
    files = files or {}
    findings: list[Finding] = []

    # Per-tool rules (read only the extracted tool text/schema/body).
    for tool in tools:
        findings.extend(_tp001(tool, rules["TP-001"]))
        findings.extend(_tp002(tool, rules["TP-002"]))
        findings.extend(_tp003(tool, rules["TP-003"]))
        findings.extend(_tp004(tool, rules["TP-004"]))
        findings.extend(_op001(tool, rules["OP-001"]))
        findings.extend(_op002(tool, rules["OP-002"]))
        if "PM-001" in rules:
            findings.extend(_pm001(tool, rules["PM-001"]))
        if "CI-001" in rules:
            findings.extend(_ci001(tool, rules["CI-001"]))
        if "SQ-001" in rules:
            findings.extend(_sq001(tool, rules["SQ-001"]))
        if "DB-001" in rules:
            findings.extend(_db001(tool, rules["DB-001"]))
        if "DB-002" in rules:
            findings.extend(_db002(tool, rules["DB-002"]))
        if "DE-001" in rules:
            findings.extend(_de001(tool, rules["DE-001"]))
        if "DL-001" in rules:
            findings.extend(_dl001(tool, rules["DL-001"]))

    # Server-level rules (need the whole tool set / a derived server name).
    if "NC-001" in rules:
        findings.extend(_nc001(tools, rules["NC-001"]))
    if "TS-001" in rules:
        findings.extend(_ts001(tools, files, rules["TS-001"]))
    if "TC-001" in rules:
        findings.extend(_tc001(tools, rules["TC-001"]))

    # File-level rules (scan raw source/config text, never execute it).
    if "CR-001" in rules:
        findings.extend(_cr001(files, rules["CR-001"]))
    if "OP-003" in rules:
        findings.extend(_op003(files, has_auth_signal, rules["OP-003"]))
    if "RP-001" in rules:
        findings.extend(_rp001(files, rules["RP-001"]))

    # ME-001 is report-level: fires once if tools exist but no auth was detected.
    if tools and not has_auth_signal:
        findings.extend(_me001(rules["ME-001"]))

    # Stamp each finding with its rule's confidence (signatures v3+). Pattern
    # heuristics are honest about being "medium"; structural checks are "high".
    for finding in findings:
        if finding.confidence is None:
            finding.confidence = rules.get(finding.id, {}).get("confidence")

    return findings


# --- helpers ---------------------------------------------------------------


def _redact(text: str, limit: int = 160) -> str:
    """Trim and scrub a snippet so secrets are never echoed in a finding."""
    scrubbed = _SECRET_RE.sub("[REDACTED]", text)
    scrubbed = scrubbed.replace("\n", " ").strip()
    if len(scrubbed) > limit:
        scrubbed = scrubbed[: limit - 1] + "…"
    return scrubbed


def _schema_text(schema: Any) -> str:
    """Flatten schema field names + descriptions into searchable text."""
    parts: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key in ("description", "title", "name") and isinstance(val, str):
                    parts.append(val)
                parts.append(str(key))
                walk(val)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(schema)
    return " ".join(parts)


def _make(
    rule: dict[str, Any],
    rule_id: str,
    tool: Tool | None,
    evidence: str,
    location: str | None = None,
) -> Finding:
    loc = location if location is not None else (tool.location if tool else "")
    return Finding(
        id=rule_id,
        category=rule["category"],
        severity=rule["severity"],
        tool_name=tool.name if tool else None,
        location=loc,
        message=rule["message"],
        evidence=_redact(evidence),
        recommendation=rule["recommendation"],
        threat_id=rule.get("threat"),
    )


def _first_match(patterns: Iterable[str], text: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


@lru_cache(maxsize=64)
def _combined(patterns: tuple[str, ...]) -> re.Pattern:
    """One precompiled alternation for file-level rules — those scan every byte
    of the target, so per-line/per-pattern re.search calls dominate audit time
    on large repos."""
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _name_tokens(name: str) -> list[str]:
    return re.split(r"[^a-z0-9]+", name.lower())


# --- rules -----------------------------------------------------------------


def _tp001(tool: Tool, rule: dict) -> list[Finding]:
    text = f"{tool.description} {_schema_text(tool.schema)}"
    hit = _first_match(rule.get("patterns", []), text)
    return [_make(rule, "TP-001", tool, hit)] if hit else []


def _tp002(tool: Tool, rule: dict) -> list[Finding]:
    text = f"{tool.name} {tool.description} {_schema_text(tool.schema)}"
    offenders = []
    for ch in text:
        if ch in _HIDDEN_CHARS:
            offenders.append(ch)
        elif unicodedata.category(ch) in ("Cc", "Cf") and ch not in ("\t", "\n", "\r"):
            offenders.append(ch)
    if not offenders:
        return []
    names = ", ".join(sorted({f"U+{ord(c):04X}" for c in offenders}))
    return [_make(rule, "TP-002", tool, f"hidden characters: {names}")]


def _tp003(tool: Tool, rule: dict) -> list[Finding]:
    text = f"{tool.description} {_schema_text(tool.schema)}"
    hit = _first_match(rule.get("patterns", []), text)
    return [_make(rule, "TP-003", tool, hit)] if hit else []


def _tp004(tool: Tool, rule: dict) -> list[Finding]:
    tokens = set(_name_tokens(tool.name))
    benign = set(rule.get("benign_name_hints", []))
    if not (tokens & benign):
        return []
    hit = _first_match(rule.get("disguised_action_patterns", []), tool.description)
    if not hit:
        return []
    return [_make(rule, "TP-004", tool, f"name '{tool.name}' but description: {hit}")]


def _op001(tool: Tool, rule: dict) -> list[Finding]:
    tokens = set(_name_tokens(tool.name))
    read_hints = set(rule.get("read_name_hints", []))
    if not (tokens & read_hints):
        return []
    hit = _first_match(rule.get("write_action_patterns", []), tool.description)
    if not hit:
        return []
    return [_make(rule, "OP-001", tool, f"read-style name '{tool.name}' but description: {hit}")]


def _op002(tool: Tool, rule: dict) -> list[Finding]:
    schema = tool.schema if isinstance(tool.schema, dict) else {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []
    dangerous = set(rule.get("dangerous_param_names", []))
    constraint_keys = set(rule.get("constraint_keys", []))
    findings: list[Finding] = []
    for pname, pdef in props.items():
        if pname.lower() not in dangerous:
            continue
        pdef = pdef if isinstance(pdef, dict) else {}
        if pdef.get("type") not in (None, "string"):
            continue
        if constraint_keys & set(pdef.keys()):
            continue
        findings.append(_make(rule, "OP-002", tool, f"unconstrained parameter '{pname}'"))
    return findings


def _me001(rule: dict) -> list[Finding]:
    return [_make(rule, "ME-001", None, "no authentication signal detected")]


# --- v2 rules: research-seeded (MCP Threat Atlas) --------------------------


def _pm001(tool: Tool, rule: dict) -> list[Finding]:
    """Preference Manipulation (MCP-T03): persuasive phrasing biasing selection."""
    text = f"{tool.description} {_schema_text(tool.schema)}"
    hit = _first_match(rule.get("patterns", []), text)
    return [_make(rule, "PM-001", tool, hit)] if hit else []


def _ci001(tool: Tool, rule: dict) -> list[Finding]:
    """Command Injection / Backdoor (MCP-T07): dangerous sink in a tool body.

    Scans the statically-captured function body text only — it is never executed.
    """
    body = getattr(tool, "body", "") or ""
    if not body:
        return []
    hit = _first_match(rule.get("sink_patterns", []), body)
    return [_make(rule, "CI-001", tool, f"dangerous sink: {hit}")] if hit else []


def _nc001(tools: list[Tool], rule: dict) -> list[Finding]:
    """Tool Name Conflict / Shadowing (MCP-T02/T06): duplicate tool names.

    Within a single target the detectable signal is collision: two or more tools
    sharing a name (the precondition for shadowing/interception).
    """
    by_name: dict[str, list[Tool]] = {}
    for tool in tools:
        by_name.setdefault(tool.name.lower(), []).append(tool)
    findings: list[Finding] = []
    for name, group in by_name.items():
        if len(group) > 1:
            note = " (shadows a common sensitive tool)" if name in {
                n.lower() for n in rule.get("shadowed_names", [])
            } else ""
            findings.append(
                _make(
                    rule,
                    "NC-001",
                    group[0],
                    f"tool name '{group[0].name}' defined {len(group)} times{note}",
                )
            )
    return findings


def _ts001(tools: list[Tool], files: dict[str, str], rule: dict) -> list[Finding]:
    """Namespace Typosquatting (MCP-T01): names near-identical to a known one."""
    known = [k.lower() for k in rule.get("known_names", [])]
    min_len = int(rule.get("min_len", 4))
    max_dist = int(rule.get("max_edit_distance", 1))

    candidates: list[tuple[str, str]] = [(t.name, t.location) for t in tools]
    pkg = _package_name(files)
    if pkg:
        candidates.append((pkg, "package manifest"))

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for raw, loc in candidates:
        name = _normalize_homoglyphs(raw.lower())
        if len(name) < min_len or name in known:
            continue
        for k in known:
            if abs(len(name) - len(k)) > max_dist:
                continue
            if name != k and _edit_distance(name, k) <= max_dist:
                key = (name, k)
                if key in seen:
                    break
                seen.add(key)
                findings.append(
                    _make(rule, "TS-001", None, f"'{raw}' resembles known name '{k}'", location=loc)
                )
                break
    return findings


def _tc001(tools: list[Tool], rule: dict) -> list[Finding]:
    """Tool Chaining Abuse (MCP-T12): a server with read + outbound-send tools."""
    read_pats = rule.get("local_read_patterns", [])
    send_pats = rule.get("network_send_patterns", [])
    reader = sender = None
    for tool in tools:
        text = f"{tool.name} {tool.description} {_schema_text(tool.schema)} {getattr(tool, 'body', '') or ''}"
        if reader is None and _first_match(read_pats, text):
            reader = tool
        if sender is None and _first_match(send_pats, text):
            sender = tool
    if reader and sender:
        ev = f"read-capable tool '{reader.name}' + network-capable tool '{sender.name}'"
        return [_make(rule, "TC-001", None, ev)]
    return []


def _cr001(files: dict[str, str], rule: dict) -> list[Finding]:
    """Credential Theft (MCP-T10): hardcoded secret literals in source/config."""
    patterns = tuple(rule.get("patterns", []))
    if not patterns:
        return []
    regex = _combined(patterns)
    findings: list[Finding] = []
    for path, text in files.items():
        m = regex.search(text)  # one finding per file is enough to flag the file
        if m:
            findings.append(
                _make(rule, "CR-001", None, m.group(0), location=f"{path}:{_line_of(text, m.start())}")
            )
    return findings


def _op003(files: dict[str, str], has_auth_signal: bool, rule: dict) -> list[Finding]:
    """Sandbox-escape precondition (MCP-T11): broad network bind, no auth."""
    if has_auth_signal:
        return []
    patterns = tuple(rule.get("bind_patterns", []))
    if not patterns:
        return []
    regex = _combined(patterns)
    for path, text in files.items():
        m = regex.search(text)
        if m:
            return [
                _make(rule, "OP-003", None, f"binds to {m.group(0)}", location=f"{path}:{_line_of(text, m.start())}")
            ]
    return []


def _rp001(files: dict[str, str], rule: dict) -> list[Finding]:
    """Rug-pull precondition (MCP-T05): floating deps and no lockfile."""
    manifests = [m.lower() for m in rule.get("manifest_files", [])]
    lockfiles = [l.lower() for l in rule.get("lockfiles", [])]
    present = [(p, t) for p, t in files.items() if any(p.lower().endswith(m) for m in manifests)]
    if not present:
        return []
    has_lock = any(any(p.lower().endswith(l) for l in lockfiles) for p in files)
    if has_lock:
        return []
    for path, text in present:
        if _first_match(rule.get("unpinned_patterns", []), text):
            return [_make(rule, "RP-001", None, "unpinned dependency versions, no lockfile", location=path)]
    return []


# --- v3 rules: database & data-leak security (spec goal: vet MCPs that touch
# --- databases so corporate data cannot leak through an agent) ---------------


def _sq001(tool: Tool, rule: dict) -> list[Finding]:
    """SQL Injection sink (MCP-T07): SQL built by interpolation in a tool body."""
    body = getattr(tool, "body", "") or ""
    if not body:
        return []
    hit = _first_match(rule.get("sql_interp_patterns", []), body)
    return [_make(rule, "SQ-001", tool, f"interpolated SQL: {hit}")] if hit else []


def _db001(tool: Tool, rule: dict) -> list[Finding]:
    """Raw SQL passthrough (MCP-T11): caller-supplied SQL reaches an exec call.

    Fires when (a) a raw-SQL-named parameter exists AND the body shows an
    execution signal, or (b) the description itself advertises arbitrary SQL.
    """
    desc_hit = _first_match(rule.get("description_patterns", []), tool.description)
    if desc_hit:
        return [_make(rule, "DB-001", tool, f"description: {desc_hit}")]

    schema = tool.schema if isinstance(tool.schema, dict) else {}
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}
    raw_params = set(rule.get("raw_sql_param_names", []))
    param = next((p for p in props if p.lower() in raw_params), None)
    if not param:
        return []
    body = getattr(tool, "body", "") or ""
    exec_hit = _first_match(rule.get("exec_signal_patterns", []), body)
    if not exec_hit:
        return []
    return [_make(rule, "DB-001", tool, f"raw-SQL parameter '{param}' reaches {exec_hit.strip()}")]


def _db002(tool: Tool, rule: dict) -> list[Finding]:
    """Destructive/admin SQL (MCP-T11): DDL/DCL capability in body or metadata."""
    text = f"{tool.description} {_schema_text(tool.schema)} {getattr(tool, 'body', '') or ''}"
    hit = _first_match(rule.get("patterns", []), text)
    return [_make(rule, "DB-002", tool, f"destructive SQL: {hit}")] if hit else []


def _de001(tool: Tool, rule: dict) -> list[Finding]:
    """Exfiltration sink (MCP-T12): data sent to a hardcoded external endpoint."""
    body = getattr(tool, "body", "") or ""
    if not body:
        return []
    known = _first_match(rule.get("exfil_host_patterns", []), body)
    if known:
        return [_make(rule, "DE-001", tool, f"known callback/exfil host: {known}")]
    url_pat = rule.get("url_pattern")
    if not url_pat:
        return []
    url = re.search(url_pat, body, re.IGNORECASE)
    if not url:
        return []
    send = _first_match(rule.get("send_patterns", []), body)
    if not send:
        return []
    return [_make(rule, "DE-001", tool, f"hardcoded endpoint {url.group(0)} + send call {send.strip()}")]


def _dl001(tool: Tool, rule: dict) -> list[Finding]:
    """Sensitive-data surface (MCP-T13): PII/credential tables and columns."""
    text = f"{tool.description} {_schema_text(tool.schema)} {getattr(tool, 'body', '') or ''}"
    hit = _first_match(rule.get("patterns", []), text)
    return [_make(rule, "DL-001", tool, f"sensitive data reference: {hit}")] if hit else []


# --- helpers for the v2 rules ----------------------------------------------

# Common homoglyph substitutions used in squatting (digit/letter lookalikes).
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "_": "-"})


def _normalize_homoglyphs(name: str) -> str:
    return name.translate(_HOMOGLYPHS)


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (small strings; iterative two-row DP)."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _package_name(files: dict[str, str]) -> str | None:
    """Best-effort static read of a package/server name from manifest files."""
    for path, text in files.items():
        low = path.lower()
        if low.endswith("package.json"):
            try:
                data = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                continue
            name = data.get("name") if isinstance(data, dict) else None
            if isinstance(name, str) and name:
                return name.split("/")[-1]
        elif low.endswith("pyproject.toml"):
            m = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                return m.group(1)
    return None
