"""Local-path input loader (spec §4, item 1).

Reads files as TEXT ONLY. Never imports, executes, installs, or evals anything in
the target. Binary files and oversized files are skipped.
"""

from __future__ import annotations

import os
from pathlib import Path

# Caps mirror the GitHub fetcher so behavior is consistent across input modes.
MAX_FILES = 2000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 25_000_000

# Extensions that can carry MCP tool definitions or agent-skill instructions.
# Markdown/shell are included so SKILL.md files and bundled install scripts are
# audited (agent skills are the same trust surface as MCP tools).
RELEVANT_EXT = (
    ".py",
    ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx",
    ".json",
    ".md", ".mdx",
    ".sh", ".bash", ".zsh", ".ps1",
)

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".mypy_cache", ".pytest_cache", "site-packages", ".tox",
}


def load_local(path: str) -> dict[str, str]:
    """Return {relative_path: text} for a local file or directory target."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Target path does not exist: {path}")

    if root.is_file():
        return _read_one(root, root.name)

    files: dict[str, str] = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if not fname.lower().endswith(RELEVANT_EXT):
                continue
            fpath = Path(dirpath) / fname
            rel = str(fpath.relative_to(root))
            chunk = _read_one(fpath, rel)
            if not chunk:
                continue
            (key, content), = chunk.items()
            total += len(content.encode("utf-8", "ignore"))
            if total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
                return files
            files[key] = content
    return files


def _read_one(fpath: Path, rel: str) -> dict[str, str]:
    try:
        if fpath.stat().st_size > MAX_FILE_BYTES:
            return {}
        # 'replace' guarantees we never raise on odd bytes; we only read text.
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    return {rel: text}
