"""The generated encyclopedia must be self-contained and reflect the Atlas."""

from mcp_auditor.atlas import load_atlas
from mcp_auditor.encyclopedia import build_encyclopedia

HTML = build_encyclopedia(load_atlas())


def test_is_valid_self_contained_html():
    assert HTML.startswith("<!DOCTYPE html>")
    assert "<style>" in HTML            # styling is inlined
    assert "<script" not in HTML.lower()  # no scripts at all
    assert 'src="http' not in HTML       # nothing is fetched into the page


def test_the_only_remote_asset_is_the_font_sheet():
    """One <link>, and the type stacks name a fallback for when it never loads.

    The page is opened from CI artifacts and from laptops with no network, so
    it has to stay readable when the single request it makes fails.
    """
    assert HTML.count("<link") == 1
    assert HTML.count("fonts.googleapis.com") == 1
    assert "'Courier New'" in HTML and "'Impact'" in HTML


def test_wears_the_same_house_style_as_the_report():
    assert 'class="grain"' in HTML and 'class="stripes"' in HTML
    assert "#f4ead5" in HTML                              # cream is the ground
    assert "box-shadow: 6px 6px 0 var(--orange)" in HTML  # the signature block
    assert 'class="stamped"' in HTML
    assert "prefers-color-scheme" not in HTML


def test_phases_are_numbered_chapter_banners():
    for n, phase in enumerate(("Creation", "Deployment", "Operation", "Maintenance"), 1):
        assert f"// Phase {n:02d}" in HTML
        assert f"{phase} phase" in HTML
    assert 'class="tier"' in HTML


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
    # The pair is a good/bad prompt block: green is the safe pattern, red the
    # risky one, and each carries its own written tag.
    assert '<div class="prompt good" data-tag="Safer pattern">' in HTML
    assert '<div class="prompt bad" data-tag="Risky pattern">' in HTML
