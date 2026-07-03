"""Definition updater — refresh the Atlas + signatures like antivirus definitions.

`mcp-audit update` downloads the latest `signatures.yaml` and `threats.yaml` from
a canonical source into a per-user cache (``~/.mcp-audit/signatures/``). This lets
users get fresh detections WITHOUT upgrading the pip package. Audits then prefer
the cached definitions when present; pin with ``--signatures`` for reproducibility.

Only TEXT definition files are downloaded — never code, never anything executed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml

# Override with the MCP_AUDIT_DEFS_URL env var (e.g. to point at a fork/release).
DEFAULT_BASE_URL = (
    "https://raw.githubusercontent.com/Roza/mcp-auditor/main/src/mcp_auditor"
)
DEFINITION_FILES = ("signatures.yaml", "threats.yaml")
_TIMEOUT = 20


def cache_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".mcp-audit" / "signatures"


def _cached(name: str) -> Optional[Path]:
    p = cache_dir() / name
    return p if p.exists() else None


def cached_signatures_path() -> Optional[Path]:
    return _cached("signatures.yaml")


def cached_atlas_path() -> Optional[Path]:
    return _cached("threats.yaml")


def effective_signatures_path(explicit: str | Path | None) -> Optional[str]:
    """Resolve which signatures file an audit should use.

    Order: an explicit ``--signatures`` path > the updated cache > None (the
    bundled default handled by the loader).
    """
    if explicit:
        return str(explicit)
    cached = cached_signatures_path()
    return str(cached) if cached else None


def effective_atlas_path() -> Optional[str]:
    cached = cached_atlas_path()
    return str(cached) if cached else None


def update(base_url: str | None = None, session=None, dest: str | Path | None = None) -> dict:
    """Download the latest definition files into the cache. Returns a summary."""
    base = (base_url or os.environ.get("MCP_AUDIT_DEFS_URL") or DEFAULT_BASE_URL).rstrip("/")
    target = Path(dest) if dest else cache_dir()
    if session is None:
        import requests  # lazy

        session = requests.Session()

    target.mkdir(parents=True, exist_ok=True)
    written: dict[str, int] = {}
    for name in DEFINITION_FILES:
        resp = session.get(f"{base}/{name}", headers={"User-Agent": "mcp-auditor"}, timeout=_TIMEOUT)
        resp.raise_for_status()
        (target / name).write_text(resp.text, encoding="utf-8")
        written[name] = len(resp.text)

    version = _read_version(target / "signatures.yaml")
    return {"dest": str(target), "files": written, "version": version}


def _read_version(path: Path) -> Optional[int]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data.get("version") if isinstance(data, dict) else None
    except Exception:
        return None
