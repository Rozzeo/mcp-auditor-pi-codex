"""The MCP Threat Atlas loader (threats.yaml) — the research-cited source of truth.

The Atlas is the human/research face of the knowledge base: a catalog of MCP
attack classes, each with lifecycle phase, severity, mitigations, and citations.
Signature rules reference Atlas threat ids; this module resolves a finding's
`threat_id` into the concrete citation `sources` that justify it.

Loading is best-effort everywhere it is used: a missing or malformed Atlas must
never break an audit (detection still works; only the citation enrichment is lost).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml

_DEFAULT_ATLAS = Path(__file__).with_name("threats.yaml")
# Public alias: the intel autodraft pipeline writes back to the bundled Atlas.
DEFAULT_ATLAS_PATH = _DEFAULT_ATLAS


def load_atlas(path: str | Path | None = None) -> dict[str, Any]:
    """Load the Threat Atlas from YAML (defaults to the bundled file)."""
    target = Path(path) if path else _DEFAULT_ATLAS
    with open(target, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "threats" not in data:
        raise ValueError(f"Invalid Atlas file: {target}")
    return data


def load_atlas_safe(path: str | Path | None = None) -> Optional[dict[str, Any]]:
    """Load the Atlas, returning None on any error (never raises)."""
    try:
        return load_atlas(path)
    except Exception:
        return None


def threats_by_id(atlas: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {t["id"]: t for t in atlas.get("threats", []) if isinstance(t, dict) and "id" in t}


def _references(atlas: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        r["key"]: r
        for r in atlas.get("references", [])
        if isinstance(r, dict) and "key" in r
    }


def resolve_sources(atlas: dict[str, Any], threat_id: str | None) -> list[dict[str, Any]]:
    """Return citation source dicts for a threat, expanding `ref` shorthands.

    A source may be inline (e.g. a CVE) or a `{ref: <key>, section: ...}` pointer
    into the Atlas `references` table; the latter is flattened into a full record.
    """
    if not threat_id:
        return []
    threat = threats_by_id(atlas).get(threat_id)
    if not threat:
        return []
    refs = _references(atlas)
    out: list[dict[str, Any]] = []
    for src in threat.get("sources", []):
        if not isinstance(src, dict):
            continue
        if "ref" in src:
            entry = {k: v for k, v in refs.get(src["ref"], {}).items() if k != "key"}
            for key, val in src.items():
                if key != "ref":
                    entry[key] = val
            out.append(entry)
        else:
            out.append(dict(src))
    return out
