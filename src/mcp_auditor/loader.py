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
        read = _read_one(root)
        return {root.name: read[0]} if read else {}

    files: dict[str, str] = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if not fname.lower().endswith(RELEVANT_EXT):
                continue
            fpath = Path(dirpath) / fname
            read = _read_one(fpath)
            if read is None:
                continue
            text, size = read
            total += size
            if total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
                return files
            files[str(fpath.relative_to(root))] = text
    return files


def _read_one(fpath: Path) -> tuple[str, int] | None:
    """Return (text, byte size) for one file, or None if unreadable/oversized.

    The size is taken from stat() rather than re-encoding the decoded text: the
    total-bytes cap only needs a byte count, and encoding every file a second
    time just to measure it copies the whole corpus for nothing.
    """
    try:
        size = fpath.stat().st_size
        if size > MAX_FILE_BYTES:
            return None
        # 'replace' guarantees we never raise on odd bytes; we only read text.
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return text, size
