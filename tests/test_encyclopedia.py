"""The generated encyclopedia must be self-contained and reflect the Atlas."""

from mcp_auditor.atlas import load_atlas
from mcp_auditor.encyclopedia import build_encyclopedia

HTML = build_encyclopedia(load_atlas())


def test_is_valid_self_contained_html():
    assert HTML.startswith("<!DOCTYPE html>")
    assert "<style>" in HTML            # styling is inlined
    assert "<script" not in HTML.lower()  # no scripts at all
    assert 'src="http' not in HTML       # no external resources => offline


def test_lists_known_threats_with_citation_links():
    assert "MCP-T04" in HTML
    assert "Tool Poisoning" in HTML
    assert "arxiv.org/abs/2503.23278" in HTML


def test_marks_known_gaps_honestly():
    # Installer Spoofing (MCP-T08) is runtime-only — shown as a gap, not a rule.
    assert "Installer Spoofing" in HTML
    assert "known gap" in HTML


def test_teaches_reviewers_what_the_engine_can_and_cannot_establish():
    assert "Sensitive Data Flow" in HTML
    assert "What the engine can establish" in HTML
    assert "What it cannot establish" in HTML
    assert "Reviewer questions" in HTML
    assert "Safer pattern" in HTML
