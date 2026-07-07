"""GitHub repo fetcher (spec §4, item 2 — implemented LAST).

Downloads public file contents via the GitHub REST API. It only DOWNLOADS text;
it never executes, imports, installs, or evals anything. Totals are capped so a
huge repo can't exhaust memory. An optional `GITHUB_TOKEN` raises the rate limit.

Primary path is the tarball endpoint: ONE request for the whole repo (the
per-blob API is 2+N requests, which exhausts the 60/hour unauthenticated rate
limit on any medium repo). The tar is read in memory only — members are never
extracted to disk, so member paths can't traverse anywhere.
"""

from __future__ import annotations

import base64
import io
import os
import re
import tarfile

from .loader import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, RELEVANT_EXT, SKIP_DIRS

_API = "https://api.github.com"
_REPO_RE = re.compile(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$", re.IGNORECASE)
_TIMEOUT = 20
_TAR_TIMEOUT = 60


def parse_repo(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL."""
    m = _REPO_RE.search(url.strip())
    if not m:
        raise ValueError(f"Not a recognizable GitHub repo URL: {url}")
    owner, repo = m.group(1), m.group(2)
    if not owner or not repo or owner.lower() in ("orgs", "settings"):
        raise ValueError(f"Not a recognizable GitHub repo URL: {url}")
    return owner, repo


def _headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "mcp-auditor"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _is_skipped(path: str) -> bool:
    parts = path.split("/")
    return any(part in SKIP_DIRS for part in parts[:-1])


def fetch_github(url: str, session=None, token: str | None = None) -> dict[str, str]:
    """Return {path: text} for the code-relevant files in a public GitHub repo."""
    if session is None:
        import requests  # imported lazily so the rest of the tool has no hard dep at import time

        session = requests.Session()
    token = token or os.environ.get("GITHUB_TOKEN")
    owner, repo = parse_repo(url)
    headers = _headers(token)

    try:
        return _fetch_tarball(session, owner, repo, headers)
    except Exception:
        # Older mocks/proxies or a failed tar download: fall back to per-blob.
        return _fetch_blobs(session, owner, repo, headers)


def _fetch_tarball(session, owner: str, repo: str, headers: dict[str, str]) -> dict[str, str]:
    """One-request fetch: download the default-branch tarball, read it in memory."""
    resp = session.get(f"{_API}/repos/{owner}/{repo}/tarball", headers=headers, timeout=_TAR_TIMEOUT)
    resp.raise_for_status()

    files: dict[str, str] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:*") as tar:
        for member in tar:
            if not member.isfile():
                continue
            # GitHub prefixes every member with "<owner>-<repo>-<sha>/".
            path = member.name.split("/", 1)[1] if "/" in member.name else member.name
            if not path.lower().endswith(RELEVANT_EXT):
                continue
            if _is_skipped(path):
                continue
            if member.size > MAX_FILE_BYTES:
                continue
            if len(files) >= MAX_FILES or total > MAX_TOTAL_BYTES:
                break
            fh = tar.extractfile(member)
            if fh is None:
                continue
            text = fh.read().decode("utf-8", "replace")
            total += len(text.encode("utf-8", "ignore"))
            if total > MAX_TOTAL_BYTES:
                break
            files[path] = text
    return files


def _fetch_blobs(session, owner: str, repo: str, headers: dict[str, str]) -> dict[str, str]:
    """Legacy path: tree listing + one blob request per file (2+N requests)."""
    meta = session.get(f"{_API}/repos/{owner}/{repo}", headers=headers, timeout=_TIMEOUT)
    meta.raise_for_status()
    branch = meta.json().get("default_branch", "main")

    tree_resp = session.get(
        f"{_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
        headers=headers,
        timeout=_TIMEOUT,
    )
    tree_resp.raise_for_status()
    tree = tree_resp.json().get("tree", [])

    files: dict[str, str] = {}
    total = 0
    for entry in tree:
        if entry.get("type") != "blob":
            continue
        path = entry.get("path", "")
        if not path.lower().endswith(RELEVANT_EXT):
            continue
        if _is_skipped(path):
            continue
        if entry.get("size", 0) > MAX_FILE_BYTES:
            continue
        if len(files) >= MAX_FILES or total > MAX_TOTAL_BYTES:
            break

        sha = entry.get("sha")
        blob = session.get(f"{_API}/repos/{owner}/{repo}/git/blobs/{sha}", headers=headers, timeout=_TIMEOUT)
        try:
            blob.raise_for_status()
        except Exception:
            continue
        text = _decode_blob(blob.json())
        if text is None:
            continue
        total += len(text.encode("utf-8", "ignore"))
        if total > MAX_TOTAL_BYTES:
            break
        files[path] = text

    return files


def _decode_blob(payload: dict) -> str | None:
    content = payload.get("content")
    if content is None:
        return None
    if payload.get("encoding") == "base64":
        try:
            return base64.b64decode(content).decode("utf-8", "replace")
        except (ValueError, base64.binascii.Error):
            return None
    return str(content)
