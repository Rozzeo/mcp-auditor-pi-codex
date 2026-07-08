"""arXiv intel source — fetch recent MCP-security papers as threat candidates.

Uses the free, key-less arXiv Atom API. Parsing is split from fetching so the
parser can be unit-tested against a saved feed with no network.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

from .model import Candidate, classify_venue, match_keywords

ARXIV_API = "http://export.arxiv.org/api/query"
_ARXIV_NS = "{http://arxiv.org/schemas/atom}"
DEFAULT_QUERY = (
    'all:"Model Context Protocol" AND '
    "(security OR attack OR poisoning OR injection OR vulnerability OR exploit)"
)
_TIMEOUT = 20
_ATOM = "{http://www.w3.org/2005/Atom}"
_ARXIV_ID_RE = re.compile(r"(\d{4}\.\d{4,5})(v\d+)?")


def build_query_url(query: str = DEFAULT_QUERY, max_results: int = 20) -> str:
    params = {
        "search_query": query,
        "start": 0,
        "max_results": max_results,
        "sortBy": "submittedDate",
        "sortOrder": "descending",
    }
    return f"{ARXIV_API}?{urlencode(params)}"


def _arxiv_id(id_url: str) -> str:
    m = _ARXIV_ID_RE.search(id_url or "")
    return m.group(1) if m else ""


def _collapse(text: str) -> str:
    return " ".join((text or "").split())


def parse_atom(feed_text: str, keywords: list[str] | None = None) -> list[Candidate]:
    """Parse an arXiv Atom feed into Candidates (no network)."""
    root = ET.fromstring(feed_text)
    candidates: list[Candidate] = []
    for entry in root.findall(f"{_ATOM}entry"):
        title = _collapse(entry.findtext(f"{_ATOM}title") or "")
        summary = _collapse(entry.findtext(f"{_ATOM}summary") or "")
        id_url = (entry.findtext(f"{_ATOM}id") or "").strip()
        published = (entry.findtext(f"{_ATOM}published") or "").strip()
        # Acceptance venue, when the authors recorded it ("Accepted at NDSS 2026").
        journal_ref = _collapse(entry.findtext(f"{_ARXIV_NS}journal_ref") or "")
        comment = _collapse(entry.findtext(f"{_ARXIV_NS}comment") or "")
        venue, tier = classify_venue(f"{journal_ref} {comment}")
        candidates.append(
            Candidate(
                source="arxiv",
                ident=_arxiv_id(id_url),
                title=title,
                summary=summary,
                url=id_url,
                published=published,
                matched=match_keywords(f"{title} {summary}", keywords),
                venue=venue,
                tier=tier,
            )
        )
    return candidates


def fetch(query: str = DEFAULT_QUERY, max_results: int = 20, session=None) -> list[Candidate]:
    """Fetch and parse recent candidate papers from arXiv (read-only HTTP GET)."""
    if session is None:
        import requests  # lazy: keeps the import-time dependency surface small

        session = requests.Session()
    resp = session.get(
        build_query_url(query, max_results),
        headers={"User-Agent": "mcp-auditor"},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return parse_atom(resp.text)
