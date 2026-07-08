"""Hacker News intel source — hour-fresh community signal.

Uses the free, key-less Algolia HN search API. Researchers announce new MCP
attack write-ups here within hours; the queue tier is "community" (fresh, not
peer-reviewed). Read-only HTTP GETs; nothing is executed.
"""

from __future__ import annotations

from urllib.parse import urlencode

from .model import Candidate, match_keywords

HN_API = "https://hn.algolia.com/api/v1/search_by_date"
_TIMEOUT = 20

# Each query is one API call; keep the list short and MCP-specific.
DEFAULT_QUERIES = [
    '"model context protocol"',
    '"MCP server" security',
]


def build_query_url(query: str, hits: int = 30) -> str:
    return f"{HN_API}?{urlencode({'query': query, 'tags': 'story', 'hitsPerPage': hits})}"


def parse_hits(payload: dict, keywords: list[str] | None = None) -> list[Candidate]:
    """Parse an Algolia response into keyword-matched Candidates (no network)."""
    out: list[Candidate] = []
    for hit in payload.get("hits", []) if isinstance(payload, dict) else []:
        if not isinstance(hit, dict):
            continue
        title = " ".join((hit.get("title") or "").split())
        text = " ".join((hit.get("story_text") or "").split())
        object_id = str(hit.get("objectID") or "")
        matched = match_keywords(f"{title} {text}", keywords)
        if not matched or not object_id:
            continue
        out.append(
            Candidate(
                source="hn",
                ident=f"hn-{object_id}",
                title=title,
                summary=text[:500] or (hit.get("url") or ""),
                url=hit.get("url") or f"https://news.ycombinator.com/item?id={object_id}",
                published=hit.get("created_at", ""),
                matched=matched,
                venue="Hacker News",
                tier="community",
            )
        )
    return out


def fetch(queries: list[str] | None = None, session=None) -> list[Candidate]:
    """Fetch fresh MCP-security stories (best-effort per query)."""
    if session is None:
        import requests  # lazy

        session = requests.Session()
    out: list[Candidate] = []
    seen: set[str] = set()
    for query in queries or DEFAULT_QUERIES:
        try:
            resp = session.get(build_query_url(query), headers={"User-Agent": "mcp-auditor"}, timeout=_TIMEOUT)
            resp.raise_for_status()
            for cand in parse_hits(resp.json()):
                if cand.ident not in seen:
                    seen.add(cand.ident)
                    out.append(cand)
        except Exception:
            continue
    return out
