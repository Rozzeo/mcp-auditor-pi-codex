"""Tests for the intel pipeline: offline parsing, dedup, queue, distill."""

from mcp_auditor.atlas import load_atlas
from mcp_auditor.intel import advisories, arxiv, distill
from mcp_auditor.intel import queue as q
from mcp_auditor.intel.model import Candidate

ATOM = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
 <entry>
  <id>http://arxiv.org/abs/2509.00001v1</id>
  <title>Tool Poisoning in MCP</title>
  <summary>We analyze tool poisoning and prompt injection in Model Context Protocol servers.</summary>
  <published>2025-09-01T00:00:00Z</published>
 </entry>
 <entry>
  <id>http://arxiv.org/abs/2503.23278v3</id>
  <title>MCP Landscape survey</title>
  <summary>A survey of supply chain risks.</summary>
  <published>2025-03-30T00:00:00Z</published>
 </entry>
</feed>"""

OSV = {
    "vulns": [
        {"id": "CVE-2025-54136", "summary": "MCPoison", "details": "rug pull", "published": "2025-08-01"}
    ]
}


def test_arxiv_parse_extracts_ids_and_keywords():
    cands = arxiv.parse_atom(ATOM)
    assert cands[0].ident == "2509.00001"
    assert cands[0].source == "arxiv"
    assert "tool poisoning" in cands[0].matched


def test_arxiv_build_query_url_is_sorted_by_date():
    url = arxiv.build_query_url(max_results=5)
    assert "sortBy=submittedDate" in url
    assert "max_results=5" in url


def test_osv_parse():
    cands = advisories.parse_osv(OSV, "mcp")
    assert cands[0].ident == "CVE-2025-54136"
    assert cands[0].source == "osv"


def test_dedup_drops_already_cited_atlas_sources():
    deduped = q.dedup(arxiv.parse_atom(ATOM), atlas=load_atlas())
    idents = {c.ident for c in deduped}
    assert "2503.23278" not in idents  # already cited in the Atlas
    assert "2509.00001" in idents


def test_queue_add_dedups_and_roundtrips(tmp_path):
    path = tmp_path / "queue.jsonl"
    atlas = load_atlas()
    new = q.add_candidates(str(path), arxiv.parse_atom(ATOM), atlas=atlas)
    assert {c.ident for c in new} == {"2509.00001"}
    # Re-adding the same candidates yields nothing new (deduped vs the queue).
    again = q.add_candidates(str(path), arxiv.parse_atom(ATOM), atlas=atlas)
    assert again == []
    loaded = q.load_queue(str(path))
    assert {c.ident for c in loaded} == {"2509.00001"}


def test_distill_manual_path_is_offline_by_default():
    res = distill.distill(Candidate("arxiv", "2509.00001", "t", "abstract"))
    assert res["status"] == "manual"
    assert "ident" in res


# --- publication-quality ranking ---------------------------------------------

from mcp_auditor.intel.model import classify_venue, filter_by_min_tier  # noqa: E402

VENUE_ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">
  <entry>
    <id>http://arxiv.org/abs/2601.11111v1</id>
    <title>Accepted MCP attack paper</title>
    <summary>Tool poisoning in the Model Context Protocol.</summary>
    <published>2026-01-01T00:00:00Z</published>
    <arxiv:comment>Accepted at USENIX Security 2026</arxiv:comment>
  </entry>
  <entry>
    <id>http://arxiv.org/abs/2601.22222v1</id>
    <title>Unreviewed preprint</title>
    <summary>Prompt injection ideas for MCP servers.</summary>
    <published>2026-01-02T00:00:00Z</published>
  </entry>
</feed>
"""


def test_classify_venue_tiers():
    assert classify_venue("Accepted at USENIX Security 2026") == ("USENIX Security", "top")
    assert classify_venue("To appear in Proceedings of NDSS 2026") == ("NDSS", "top")
    assert classify_venue("IEEE Transactions on Dependable and Secure Computing") == ("IEEE TDSC", "top")
    assert classify_venue("Presented at ACSAC") == ("ACSAC", "ranked")
    assert classify_venue("12 pages, 3 figures") == ("", "preprint")
    assert classify_venue("") == ("", "preprint")


def test_arxiv_parse_reads_acceptance_venue():
    accepted, preprint = arxiv.parse_atom(VENUE_ATOM)
    assert accepted.venue == "USENIX Security" and accepted.tier == "top"
    assert preprint.venue == "" and preprint.tier == "preprint"


def test_min_tier_filter_keeps_advisories():
    top = Candidate("arxiv", "1", "t", "s", tier="top")
    pre = Candidate("arxiv", "2", "t", "s", tier="preprint")
    cve = Candidate("osv", "CVE-1", "t", "s", tier="advisory")
    kept = filter_by_min_tier([top, pre, cve], "top")
    assert kept == [top, cve]
    assert filter_by_min_tier([top, pre, cve], "preprint") == [top, pre, cve]


def test_osv_candidates_are_advisory_tier():
    payload = {"vulns": [{"id": "CVE-2026-1", "summary": "x", "details": "y"}]}
    (cand,) = advisories.parse_osv(payload, package="mcp")
    assert cand.tier == "advisory"


def test_candidate_roundtrip_preserves_tier(tmp_path):
    c = Candidate("arxiv", "3", "t", "s", venue="NDSS", tier="top")
    assert Candidate.from_dict(c.to_dict()).tier == "top"
    # Old queue entries without the new fields still load.
    old = Candidate.from_dict({"source": "arxiv", "ident": "4", "title": "t", "summary": "s"})
    assert old.tier == "" and old.venue == ""


# --- fast sources: researcher blogs + Hacker News ------------------------------

from mcp_auditor.intel import feeds, hackernews  # noqa: E402

RSS_SAMPLE = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <item>
    <title>New MCP tool poisoning technique in the wild</title>
    <description>We found tool poisoning against an MCP server used in prod.</description>
    <link>https://blog.example/mcp-poisoning</link>
    <pubDate>Tue, 07 Jul 2026 10:00:00 GMT</pubDate>
  </item>
  <item>
    <title>Our new office plants</title>
    <description>Totally unrelated post.</description>
    <link>https://blog.example/plants</link>
  </item>
</channel></rss>
"""

ATOM_BLOG_SAMPLE = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Prompt injection via MCP server metadata</title>
    <summary>Indirect prompt injection through tool descriptions.</summary>
    <link href="https://blog.example/atom-mcp"/>
    <published>2026-07-07T00:00:00Z</published>
  </entry>
</feed>
"""


def test_feeds_parse_rss_keeps_only_keyword_hits():
    (cand,) = feeds.parse_feed(RSS_SAMPLE, "Example Blog")
    assert cand.source == "blog" and cand.tier == "community"
    assert cand.venue == "Example Blog"
    assert cand.ident == "https://blog.example/mcp-poisoning"
    assert "tool poisoning" in cand.matched


def test_feeds_parse_atom_variant():
    (cand,) = feeds.parse_feed(ATOM_BLOG_SAMPLE, "Example Atom")
    assert cand.url == "https://blog.example/atom-mcp"
    assert cand.tier == "community"


def test_feeds_malformed_xml_returns_empty():
    assert feeds.parse_feed("<not-xml", "X") == []


def test_hn_parse_hits_filters_and_builds_urls():
    payload = {"hits": [
        {"objectID": "1", "title": "MCP server security disaster", "story_text": "",
         "url": "", "created_at": "2026-07-07T01:00:00Z"},
        {"objectID": "2", "title": "Show HN: my todo app", "story_text": ""},
    ]}
    (cand,) = hackernews.parse_hits(payload)
    assert cand.ident == "hn-1" and cand.tier == "community"
    assert cand.url == "https://news.ycombinator.com/item?id=1"


def test_community_tier_ordering_in_filter():
    from mcp_auditor.intel.model import filter_by_min_tier

    blog = Candidate("blog", "b", "t", "s", tier="community")
    pre = Candidate("arxiv", "p", "t", "s", tier="preprint")
    assert filter_by_min_tier([blog, pre], "community") == [blog]
    assert filter_by_min_tier([blog, pre], "ranked") == []
