"""The shared candidate model produced by every intel source."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Candidate:
    """A piece of fetched threat intelligence awaiting human curation.

    `ident` is the stable identifier used for deduplication against the Atlas
    (an arXiv id like ``2503.23278`` or a CVE/advisory id like ``CVE-2025-54136``).
    """

    source: str               # "arxiv" | "osv" | ...
    ident: str                # arxiv id / CVE id (stable, used for dedup)
    title: str
    summary: str
    url: str = ""
    published: str = ""
    matched: list[str] = field(default_factory=list)   # which keywords hit

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "ident": self.ident,
            "title": self.title,
            "summary": self.summary,
            "url": self.url,
            "published": self.published,
            "matched": self.matched,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Candidate":
        return cls(
            source=data.get("source", ""),
            ident=data.get("ident", ""),
            title=data.get("title", ""),
            summary=data.get("summary", ""),
            url=data.get("url", ""),
            published=data.get("published", ""),
            matched=list(data.get("matched", [])),
        )


# Keywords that flag a paper/advisory as MCP-security-relevant. Extend freely;
# a hit does not auto-encode anything, it only surfaces the item for review.
KEYWORDS = [
    "tool poisoning",
    "prompt injection",
    "indirect prompt injection",
    "rug pull",
    "over-privilege",
    "over privileged",
    "typosquat",
    "name collision",
    "shadowing",
    "sandbox escape",
    "command injection",
    "credential",
    "token theft",
    "preference manipulation",
    "supply chain",
    "tool chaining",
    "parasitic",
    "mcp server",
    "model context protocol",
]


def match_keywords(text: str, keywords: list[str] | None = None) -> list[str]:
    """Return the keywords (case-insensitive) present in `text`."""
    keywords = keywords if keywords is not None else KEYWORDS
    low = text.lower()
    return [kw for kw in keywords if kw.lower() in low]
