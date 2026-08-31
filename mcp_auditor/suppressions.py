"""Auditor-side suppressions — the explicit false-positive escape hatch.

Design decisions (deliberate, security-relevant):

* Suppressions are loaded ONLY from a file the auditor passes explicitly
  (``--suppress FILE`` / ``suppressions_path=``). A ``.mcp-audit.yaml`` found
  inside the audited target is never honored automatically — otherwise a
  malicious server could ship suppressions for its own findings.
* Every entry must carry a non-empty ``reason``. A suppression nobody can
  justify is itself a smell.
* Suppressed findings are not deleted: they stay in the report flagged
  ``suppressed: true`` with the reason, and are excluded from the score,
  the severity summary, and ``--fail-on``. Transparency over silence.

File shape (YAML)::

    suppress:
      - rule: TP-001            # required: rule id
        tool: read_file          # optional: only this tool (omit = any)
        reason: "docstring quotes an attack example; not agent-directed"
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .types import Finding


class SuppressionError(ValueError):
    """Raised when a suppression file is malformed."""


def load_suppressions(path: str | Path) -> list[dict[str, Any]]:
    """Load and validate a suppression file; raise SuppressionError if invalid."""
    target = Path(path)
    if not target.exists():
        raise SuppressionError(f"Suppression file not found: {target}")
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SuppressionError(f"Suppression file is not valid YAML: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("suppress"), list):
        raise SuppressionError(
            f"Suppression file must be a mapping with a 'suppress' list: {target}"
        )

    entries: list[dict[str, Any]] = []
    for i, raw in enumerate(data["suppress"]):
        if not isinstance(raw, dict):
            raise SuppressionError(f"suppress[{i}] must be a mapping")
        rule = raw.get("rule")
        reason = raw.get("reason")
        if not isinstance(rule, str) or not rule.strip():
            raise SuppressionError(f"suppress[{i}] is missing a 'rule' id")
        if not isinstance(reason, str) or not reason.strip():
            raise SuppressionError(
                f"suppress[{i}] ({rule}) is missing a 'reason' — every "
                "suppression must be justified"
            )
        tool = raw.get("tool")
        if tool is not None and not isinstance(tool, str):
            raise SuppressionError(f"suppress[{i}] ({rule}): 'tool' must be a string")
        entries.append({"rule": rule.strip(), "tool": tool, "reason": reason.strip()})
    return entries


def apply_suppressions(findings: list[Finding], entries: list[dict[str, Any]]) -> int:
    """Mark matching findings suppressed in place; return how many matched."""
    matched = 0
    for finding in findings:
        for entry in entries:
            if entry["rule"] != finding.id:
                continue
            if entry["tool"] is not None and entry["tool"] != finding.tool_name:
                continue
            finding.suppressed = True
            finding.suppress_reason = entry["reason"]
            matched += 1
            break
    return matched
