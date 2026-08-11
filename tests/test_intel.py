"""Tests for the intel pipeline: offline parsing, dedup, queue, distill."""

from click.testing import CliRunner

from mcp_auditor.atlas import load_atlas
from mcp_auditor.cli import main
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


# --- LLM distillation (Anthropic only) ----------------------------------------


def test_distill_calls_anthropic_with_the_default_model(monkeypatch):
    calls = []
    monkeypatch.setattr(distill, "_call_anthropic",
                        lambda c, m: calls.append(m) or {"status": "drafted"})
    distill.distill(Candidate("arxiv", "1", "t", "s"), use_llm=True)
    assert calls == [distill.DEFAULT_MODEL]


def test_distill_model_override_is_respected(monkeypatch):
    seen = {}
    monkeypatch.setattr(distill, "_call_anthropic",
                        lambda c, m: seen.setdefault("model", m) or {"status": "drafted"})
    distill.distill(Candidate("arxiv", "3", "t", "s"), use_llm=True, model="claude-custom")
    assert seen["model"] == "claude-custom"


def test_no_second_provider_can_be_auto_selected(monkeypatch):
    """A provider that defaults to itself with no key set decides where abstracts
    go based on whatever credential happens to be in the environment. There is
    one provider, and it is chosen explicitly."""
    assert not hasattr(distill, "_pick_provider")
    assert not hasattr(distill, "_call_gemini")


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


# --- autodraft: included/excluded criteria gate + staging output ---------------

from mcp_auditor.intel import autodraft as ad  # noqa: E402


def test_autodraft_excludes_community_and_preprint_tiers():
    blog = Candidate("blog", "b1", "t", "s", tier="community", matched=["mcp server"])
    preprint = Candidate("arxiv", "p1", "t", "s", tier="preprint", matched=["mcp server"])
    result = ad.autodraft([blog, preprint], use_llm=True, atlas={"references": [], "threats": []})
    reasons = {e["ident"]: e["reason"] for e in result.excluded}
    assert reasons == {"b1": "tier_below_threshold", "p1": "tier_below_threshold"}
    assert result.included == []


def test_autodraft_excludes_already_cited_and_no_keyword():
    cited = Candidate("arxiv", "2503.23278", "t", "s", tier="top", matched=["mcp server"])
    unmatched = Candidate("arxiv", "x1", "t", "s", tier="top", matched=[])
    result = ad.autodraft([cited, unmatched], use_llm=True, atlas=load_atlas())
    reasons = {e["ident"]: e["reason"] for e in result.excluded}
    assert reasons["2503.23278"] == "already_in_atlas"
    assert reasons["x1"] == "no_keyword_match"


def test_autodraft_excludes_everything_when_llm_disabled():
    cand = Candidate("osv", "CVE-2026-9", "t", "s", tier="advisory", matched=["mcp"])
    result = ad.autodraft([cand], use_llm=False, atlas={"references": [], "threats": []})
    assert result.included == []
    assert result.excluded == [{"ident": "CVE-2026-9", "title": "t", "reason": "llm_disabled"}]


def test_autodraft_includes_top_tier_candidate_with_llm(monkeypatch):
    cand = Candidate("arxiv", "2601.99999", "New MCP attack", "abstract", tier="top", matched=["mcp server"])

    def fake_distill(candidate, use_llm=False, cache_dir=None, provider=None, model=None):
        return {
            "status": "drafted",
            "ident": candidate.ident,
            "threat_name": "Fake Attack",
            "lifecycle_phase": "runtime_execution",
            "static_signals": ["suspicious pattern X"],
            "draft_patterns": ["regex-for-x"],
        }

    monkeypatch.setattr(ad, "distill", fake_distill)
    result = ad.autodraft([cand], use_llm=True, atlas={"references": [], "threats": []})
    assert result.excluded == []
    (draft,) = result.included
    assert draft["status"] == "auto-drafted" and draft["needs_review"] is True
    assert draft["name"] == "Fake Attack"
    assert draft["source"]["ident"] == "2601.99999"


def test_autodraft_flags_malformed_and_empty_llm_output(monkeypatch):
    malformed = Candidate("arxiv", "m1", "t", "s", tier="top", matched=["mcp"])
    empty = Candidate("arxiv", "e1", "t", "s", tier="top", matched=["mcp"])

    def fake_distill(candidate, use_llm=False, cache_dir=None, provider=None, model=None):
        if candidate.ident == "m1":
            return {"raw": "not json", "status": "drafted", "ident": "m1"}
        return {"status": "drafted", "ident": "e1", "static_signals": [], "draft_patterns": []}

    monkeypatch.setattr(ad, "distill", fake_distill)
    result = ad.autodraft([malformed, empty], use_llm=True, atlas={"references": [], "threats": []})
    reasons = {e["ident"]: e["reason"] for e in result.excluded}
    assert reasons["m1"] == "malformed_llm_output"
    assert reasons["e1"] == "nothing_statically_detectable"


def test_write_drafts_roundtrips_yaml(tmp_path):
    path = tmp_path / "drafts" / "threats.draft.yaml"
    drafts = [{"id": "AUTO-X1", "name": "Test", "needs_review": True}]
    ad.write_drafts(str(path), drafts)
    import yaml

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded == {"drafts": drafts}


_ATLAS_FIXTURE = '''# =============================================================================
# Hand-written header comment that a full YAML round-trip would destroy.
# =============================================================================
version: 5
released: "2026-07-26"

references:
  - key: mcp-survey
    type: paper
    title: "Example survey"

threats:
  # --- Creation phase --------------------------------------------------------
  - id: MCP-T01
    name: "Existing threat"
    severity: high
    summary: "An existing, human-curated entry."
    static_detectability: "partial"
    rules: ["ME-001"]
    sources:
      - {ref: mcp-survey, section: "1.1"}
'''


def test_merge_into_atlas_appends_bumps_version_and_preserves_comments(tmp_path):
    path = tmp_path / "threats.yaml"
    path.write_text(_ATLAS_FIXTURE, encoding="utf-8")

    drafts = [
        {
            "id": "AUTO-ARXIV-2601-99999",
            "name": "Fake Auto Threat",
            "summary": "A fake auto-drafted threat for testing.",
            "lifecycle": "runtime_execution",
            "static_signals": ["suspicious pattern X"],
            "draft_patterns": ["regex-for-x"],
            "source": {
                "source": "arxiv", "ident": "2601.99999", "title": "New MCP attack",
                "url": "https://arxiv.org/abs/2601.99999", "venue": "NDSS", "tier": "top",
            },
        }
    ]
    n = ad.merge_into_atlas(drafts, atlas_path=str(path))
    assert n == 1

    text = path.read_text(encoding="utf-8")
    assert "Hand-written header comment that a full YAML round-trip would destroy." in text
    assert "version: 6" in text
    import datetime

    assert f'released: "{datetime.date.today().isoformat()}"' in text

    import yaml

    loaded = yaml.safe_load(text)
    assert loaded["version"] == 6
    ids = {t["id"] for t in loaded["threats"]}
    assert {"MCP-T01", "AUTO-ARXIV-2601-99999"} == ids
    new = next(t for t in loaded["threats"] if t["id"] == "AUTO-ARXIV-2601-99999")
    assert new["rules"] == []
    assert new["needs_review"] is True
    assert new["static_signals"] == ["suspicious pattern X"]


def test_merge_into_atlas_noop_on_empty_drafts(tmp_path):
    path = tmp_path / "threats.yaml"
    path.write_text(_ATLAS_FIXTURE, encoding="utf-8")
    n = ad.merge_into_atlas([], atlas_path=str(path))
    assert n == 0
    assert path.read_text(encoding="utf-8") == _ATLAS_FIXTURE


# --- LLM-free human curation path -----------------------------------------------


def test_build_human_draft_is_needs_review_false():
    cand = Candidate("blog", "https://blog.example/x", "Cool MCP attack post",
                      "long summary text", url="https://blog.example/x",
                      venue="Example Blog", tier="community", matched=["mcp server"])
    draft = ad.build_human_draft(cand, name="Blog Attack", lifecycle="operation", static_signal="weird pattern")
    assert draft["status"] == "human-curated"
    assert draft["needs_review"] is False
    assert draft["id"] == "HUMAN-HTTPS-BLOG-EXAMPLE-X"
    assert draft["static_signals"] == ["weird pattern"]
    assert draft["source"]["tier"] == "community"


def test_human_curated_entry_merges_without_review_badge(tmp_path):
    path = tmp_path / "threats.yaml"
    path.write_text(_ATLAS_FIXTURE, encoding="utf-8")
    cand = Candidate("hn", "hn-1", "Neat MCP finding", "summary", url="https://news.ycombinator.com/item?id=1",
                      venue="Hacker News", tier="community", matched=["mcp server"])
    draft = ad.build_human_draft(cand, name="HN Finding", lifecycle="operation")
    ad.merge_into_atlas([draft], atlas_path=str(path))

    import yaml

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    new = next(t for t in loaded["threats"] if t["id"] == "HUMAN-HN-1")
    assert new["status"] == "human-curated"
    assert new["needs_review"] is False
    assert new["rules"] == []


def test_cli_intel_curate_approve_then_skip(tmp_path):
    atlas_path = tmp_path / "threats.yaml"
    atlas_path.write_text(_ATLAS_FIXTURE, encoding="utf-8")
    queue_path = tmp_path / "queue.jsonl"
    q.save_queue(str(queue_path), [
        Candidate("hn", "hn-1", "First finding", "summary one", tier="community", matched=["mcp"]),
        Candidate("hn", "hn-2", "Second finding", "summary two", tier="community", matched=["mcp"]),
    ])

    # candidate 1: approve, accept default name/lifecycle, skip static signal.
    # candidate 2: decline.
    result = CliRunner().invoke(
        main,
        ["intel", "curate", "--queue", str(queue_path), "--atlas", str(atlas_path)],
        input="y\n\n\n\nn\n",
    )
    assert result.exit_code == 0, result.output

    import yaml

    loaded = yaml.safe_load(atlas_path.read_text(encoding="utf-8"))
    ids = {t["id"] for t in loaded["threats"]}
    assert "HUMAN-HN-1" in ids
    assert "HUMAN-HN-2" not in ids

    left = q.load_queue(str(queue_path))
    assert left == []  # both candidates were decided (one merged, one declined)
