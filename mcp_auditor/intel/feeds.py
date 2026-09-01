"""Blog/RSS intel source — the FAST channel.

Academic papers lag reality by months; the newest MCP attack techniques are
published first on security researchers' blogs. This source polls a curated
list of RSS/Atom feeds and keyword-filters the entries into Candidates
(tier "community": fresh but not peer-reviewed — triage accordingly).

Parsing is split from fetching so it can be unit-tested against saved feeds
with no network. Read-only HTTP GETs; nothing is executed.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .model import Candidate, match_keywords

_TIMEOUT = 20
_ATOM = "{http://www.w3.org/2005/Atom}"

# Curated feeds that regularly break MCP/LLM-agent attack research first.
# Extend freely — an entry only surfaces for review when a keyword matches.
DEFAULT_FEEDS: list[tuple[str, str]] = [
    ("Embrace The Red", "https://embracethered.com/blog/index.xml"),
    ("Simon Willison", "https://simonwillison.net/atom/everything/"),
    ("Invariant Labs", "https://invariantlabs.ai/rss.xml"),
    ("Trail of Bits", "https://blog.trailofbits.com/feed/"),
    ("Snyk Labs", "https://snyk.io/blog/feed.xml"),
]


def _collapse(text: str) -> str:
    return " ".join((text or "").split())


def _text(el, *names: str) -> str:
    for name in names:
        found = el.find(name)
        if found is not None:
            return _collapse("".join(found.itertext()))
    return ""


def parse_feed(feed_text: str, feed_name: str, keywords: list[str] | None = None) -> list[Candidate]:
    """Parse one RSS 2.0 or Atom feed into keyword-matched Candidates (no network)."""
    try:
        root = ET.fromstring(feed_text)
    except ET.ParseError:
        return []

    entries = []
    # RSS 2.0: <rss><channel><item>; Atom: <feed><entry>.
    for item in root.iter("item"):
        link = _text(item, "link")
        entries.append((
            _text(item, "title"),
            _text(item, "description"),
            link,
            _text(item, "pubDate"),
        ))
    for entry in root.iter(f"{_ATOM}entry"):
        link_el = entry.find(f"{_ATOM}link")
        link = (link_el.get("href") if link_el is not None else "") or _text(entry, f"{_ATOM}id")
        entries.append((
            _text(entry, f"{_ATOM}title"),
            _text(entry, f"{_ATOM}summary", f"{_ATOM}content"),
            link,
            _text(entry, f"{_ATOM}published", f"{_ATOM}updated"),
        ))

    out: list[Candidate] = []
    for title, summary, link, published in entries:
        matched = match_keywords(f"{title} {summary}", keywords)
        if not matched:
            continue  # general blogs: only keyword hits are worth review time
        out.append(
            Candidate(
                source="blog",
                ident=link,  # the post URL is the stable dedup id
                title=title,
                summary=summary[:500],
                url=link,
                published=published,
                matched=matched,
                venue=feed_name,
                tier="community",
            )
        )
    return out


def fetch(feeds: list[tuple[str, str]] | None = None, session=None) -> list[Candidate]:
    """Fetch all curated feeds (best-effort per feed; one failure never sinks the rest)."""
    if session is None:
        import requests  # lazy

        session = requests.Session()
    out: list[Candidate] = []
    for name, url in feeds or DEFAULT_FEEDS:
        try:
            resp = session.get(url, headers={"User-Agent": "mcp-auditor"}, timeout=_TIMEOUT)
            resp.raise_for_status()
            out.extend(parse_feed(resp.text, name))
        except Exception:
            continue
    return out
