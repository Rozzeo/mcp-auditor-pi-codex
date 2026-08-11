"""Provenance for a doc-derived tool list — is each name actually on the page?

A hosted connector often has no source to read, so its catalogue is transcribed
from the vendor's documentation. That transcription is a model's reading of
prose, and until something checks it, the matrix carries names nobody confirmed.
The objection to reading docs was never that a model does the reading; it was
that the result had nothing to check it against.

This module is that check, and it is deterministic: refetch the page named in the
tools file's `_source`, reduce it to text, and assert that every tool name
appears there. A hallucinated `wpcom-delete-site` is not on the page and reaches
the review board marked NOT ON PAGE rather than sitting in the sheet looking
exactly like the 82 real rows around it.

The page is documentation, not the server. Fetching it is the same class of
network access as `fetch_github`; the connector under review is still never
started and never contacted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlparse

_URL = re.compile(r"^\s*https?://", re.IGNORECASE)
_TIMEOUT = 20

# Bare verbs and stock nouns that occur in any technical prose. Matching one of
# these proves nothing, so a name is never confirmed on such a fragment alone —
# `-> action: list` is verified by its facade, not by the word "list".
_GENERIC = frozenset({
    "list", "get", "set", "add", "new", "all", "run", "use", "api", "mcp",
    "read", "write", "delete", "create", "update", "search", "query", "status",
    "count", "describe", "discover", "action", "tool", "tools", "name", "type",
})


class _TextExtractor(HTMLParser):
    """Tags out, text kept. Script and style bodies are dropped — a tool name
    that only occurs inside a bundled JS blob is not documentation.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._muted = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style", "noscript"):
            self._muted += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript") and self._muted:
            self._muted -= 1

    def handle_data(self, data: str) -> None:
        if not self._muted:
            self._chunks.append(data)

    def text(self) -> str:
        return " ".join(self._chunks)


def page_text(html: str) -> str:
    """Reduce a documentation page to searchable text."""
    parser = _TextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # A malformed page still yields whatever was parsed before the error;
        # falling back to the raw markup would match names inside attributes.
        pass
    return re.sub(r"\s+", " ", parser.text())


def fetch_page(url: str, session=None) -> str:
    """Download a documentation page and return it as text."""
    if session is None:
        import requests  # lazy, same as fetcher.py — no hard dep at import time

        session = requests.Session()
    resp = session.get(url, headers={"User-Agent": "mcp-auditor"}, timeout=_TIMEOUT)
    resp.raise_for_status()
    return page_text(resp.text)


def declared_source(text: str) -> str:
    """The `_source` URL a tools file claims it was transcribed from, if any."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    source = data.get("_source") or data.get("_url") or ""
    source = str(source).strip()
    return source if _URL.match(source) else ""


def _groups(name: str) -> list[list[str]]:
    """Split a tool name into the pieces that can be checked independently.

    Outer list is conjunctive, inner list is alternative: the synthesized name
    `facade -> action: list / describe` must have `facade` on the page AND
    either `list` or `describe`. The arrow form is our own notation for a facade
    operation and never appears in the vendor's prose, so matching the whole
    string would fail every facade row.
    """
    groups: list[list[str]] = []
    for piece in name.split("->"):
        piece = re.sub(r"^(?:action|operation|method)\s*:\s*", "", piece.strip(), flags=re.IGNORECASE)
        alts = [a.strip() for a in piece.split("/") if a.strip()]
        if alts:
            groups.append(alts)
    return groups


def _discriminating(alt: str) -> bool:
    return len(alt) >= 4 and alt.lower() not in _GENERIC


def _pattern(alt: str) -> re.Pattern[str]:
    """Match a tool name allowing the separator the docs happen to render.

    Vendors write `wpcom-user-sites` in a heading and `wpcom_user_sites` in a
    code block; both are the same tool. Word boundaries keep `posts.list` from
    matching inside `drafts.postslist`.
    """
    parts = [p for p in re.split(r"[-_.]+", alt) if p]
    body = r"[-_.\s]?".join(re.escape(p) for p in parts)
    return re.compile(rf"(?<!\w){body}(?!\w)", re.IGNORECASE)


def is_on_page(name: str, text: str) -> bool:
    """True when every discriminating part of `name` occurs in `text`.

    A name built only from generic fragments has nothing checkable in it and
    returns False — unconfirmed, not confirmed. Silence must never read as
    assent here; that is the failure mode this whole module exists to prevent.
    """
    checked = 0
    for alts in _groups(name):
        usable = [a for a in alts if _discriminating(a)]
        if not usable:
            continue
        checked += 1
        if not any(_pattern(alt).search(text) for alt in usable):
            return False
    return checked > 0


@dataclass
class Provenance:
    """The result of checking one tools file against the page it came from."""

    source: str = ""
    checked_at: str = ""
    status: str = "none"  # none | checked | unreachable | skipped
    found: set[str] = field(default_factory=set)
    missing: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def active(self) -> bool:
        """Whether a source column belongs in the output at all."""
        return bool(self.source)

    def cell(self, action: str) -> str:
        """The per-row provenance cell — what a reviewer needs to trust the row."""
        if not self.source:
            return ""
        if self.status == "unreachable":
            return f"UNCHECKED ({self.error}) · {self.source}"
        if self.status == "skipped":
            return f"unchecked (--no-verify) · {self.source}"
        state = "on page" if action in self.found else "NOT ON PAGE"
        return f"{state} · {self.checked_at} · {self.source}"

    def summary(self) -> str:
        if self.status == "unreachable":
            return f"could not fetch {self.source}: {self.error}"
        if self.status == "skipped":
            return f"verification skipped for {self.source}"
        total = len(self.found) + len(self.missing)
        host = urlparse(self.source).netloc or self.source
        return f"{len(self.found)}/{total} names confirmed on {host}"


def verify(names: list[str], source: str, session=None) -> Provenance:
    """Check every name against the page, returning what a reviewer can rely on.

    A page that cannot be fetched yields `unreachable` rather than an exception:
    losing the whole matrix because a docs site was briefly down would push
    people back to building the sheet by hand.
    """
    prov = Provenance(source=source)
    try:
        text = fetch_page(source, session=session)
    except Exception as exc:
        prov.status = "unreachable"
        prov.error = type(exc).__name__
        return prov

    prov.status = "checked"
    prov.checked_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for name in names:
        if is_on_page(name, text):
            prov.found.add(name)
        else:
            prov.missing.append(name)
    return prov
