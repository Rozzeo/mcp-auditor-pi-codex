"""Rule-based, explainable detection engine (spec §6).

Each rule reads only the statically-extracted tool text/schema and emits zero or
more `Finding`s. Patterns live in `signatures.yaml` so the knowledge base can be
edited without touching code. No LLM calls, no target execution.
"""

from __future__ import annotations

import re
import unicodedata
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


def run_rules(tools: list[Tool], signatures: dict[str, Any], has_auth_signal: bool) -> list[Finding]:
    """Apply every rule to every tool and return all findings."""
    rules = signatures["rules"]
    findings: list[Finding] = []

    for tool in tools:
        findings.extend(_tp001(tool, rules["TP-001"]))
        findings.extend(_tp002(tool, rules["TP-002"]))
        findings.extend(_tp003(tool, rules["TP-003"]))
        findings.extend(_tp004(tool, rules["TP-004"]))
        findings.extend(_op001(tool, rules["OP-001"]))
        findings.extend(_op002(tool, rules["OP-002"]))

    # ME-001 is report-level: fires once if tools exist but no auth was detected.
    if tools and not has_auth_signal:
        findings.extend(_me001(rules["ME-001"]))

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


def _make(rule: dict[str, Any], rule_id: str, tool: Tool | None, evidence: str) -> Finding:
    return Finding(
        id=rule_id,
        category=rule["category"],
        severity=rule["severity"],
        tool_name=tool.name if tool else None,
        location=tool.location if tool else "",
        message=rule["message"],
        evidence=_redact(evidence),
        recommendation=rule["recommendation"],
    )


def _first_match(patterns: Iterable[str], text: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


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
