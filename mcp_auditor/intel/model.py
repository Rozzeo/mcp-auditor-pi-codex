"""The shared candidate model produced by every intel source."""

from __future__ import annotations

import re
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
    # Publication-quality ranking (added for curation triage): the detected
    # venue and its tier — "advisory" | "top" | "ranked" | "preprint".
    venue: str = ""
    tier: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "ident": self.ident,
            "title": self.title,
            "summary": self.summary,
            "url": self.url,
            "published": self.published,
            "matched": self.matched,
            "venue": self.venue,
            "tier": self.tier,
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
            venue=data.get("venue", ""),
            tier=data.get("tier", ""),
        )


# --- publication-quality ranking ---------------------------------------------
#
# arXiv is a PREPRINT server — anyone can post anything. Authors of accepted
# papers usually record the venue in the `journal_ref`/`comment` metadata
# ("Accepted at USENIX Security 2026"), which is what we classify here.
#
# Tiers (freshness and verification pull in opposite directions — the tier
# says HOW to read an item, not whether it matters):
#   advisory  — a confirmed CVE/OSV vulnerability (not a paper; always kept)
#   top       — Big-4 security venues, Q1 security journals, top ML/NLP venues
#   ranked    — other known peer-reviewed security/ML venues
#   community — researcher blogs / Hacker News: hour-fresh, not peer-reviewed
#   preprint  — arXiv with no venue detected (unreviewed)

TIER_ORDER = {"advisory": 0, "top": 1, "ranked": 2, "community": 3, "preprint": 4, "": 4}

# (regex, canonical venue name, tier) — first match wins.
VENUE_PATTERNS: list[tuple[str, str, str]] = [
    # Big-4 security conferences
    (r"ieee (symposium on )?security (and|&) privacy|\bs&p\b|\boakland\b", "IEEE S&P", "top"),
    (r"usenix security", "USENIX Security", "top"),
    (r"\bacm ccs\b|\bccs ?20\d\d|computer and communications security", "ACM CCS", "top"),
    (r"\bndss\b|network and distributed system security", "NDSS", "top"),
    # Q1 security journals
    (r"\btifs\b|information forensics and security", "IEEE TIFS", "top"),
    (r"\btdsc\b|dependable and secure computing", "IEEE TDSC", "top"),
    (r"\btops\b|transactions on privacy and security", "ACM TOPS", "top"),
    # Top ML/NLP venues (LLM/MCP security papers often publish here)
    (r"\bneurips\b|neural information processing systems", "NeurIPS", "top"),
    (r"\bicml\b|international conference on machine learning", "ICML", "top"),
    (r"\biclr\b|international conference on learning representations", "ICLR", "top"),
    (r"\bacl 20\d\d|annual meeting of the association for computational linguistics", "ACL", "top"),
    # Solid peer-reviewed venues
    (r"\bacsac\b", "ACSAC", "ranked"),
    (r"asiaccs|asia ccs", "AsiaCCS", "ranked"),
    (r"\besorics\b", "ESORICS", "ranked"),
    (r"\braid 20\d\d|research in attacks, intrusions", "RAID", "ranked"),
    (r"\bdsn\b|dependable systems and networks", "DSN", "ranked"),
    (r"euro ?s&p|eurosp", "IEEE EuroS&P", "ranked"),
    (r"\bpets\b|privacy enhancing technologies", "PETS", "ranked"),
    (r"\bsatml\b", "IEEE SaTML", "ranked"),
    (r"\bwww 20\d\d|the web conference", "WWW", "ranked"),
    (r"\baaai\b", "AAAI", "ranked"),
    (r"\bemnlp\b", "EMNLP", "ranked"),
    (r"\bnaacl\b", "NAACL", "ranked"),
    (r"\bcolm\b", "COLM", "ranked"),
    (r"computers & security|comput\. secur\.", "Computers & Security", "ranked"),
]


def classify_venue(text: str) -> tuple[str, str]:
    """Detect (venue, tier) from arXiv journal_ref/comment text.

    Empty or unrecognized text means the paper is an unreviewed preprint.
    """
    if text and text.strip():
        for pattern, name, tier in VENUE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return name, tier
    return "", "preprint"


def filter_by_min_tier(candidates: list["Candidate"], min_tier: str) -> list["Candidate"]:
    """Keep candidates at or above `min_tier`. Advisories (real CVEs) always pass."""
    limit = TIER_ORDER.get(min_tier, 3)
    return [c for c in candidates if TIER_ORDER.get(c.tier, 3) <= limit]


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
