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
