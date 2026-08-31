"""The skill and the product must not drift apart.

`skills/retro-futurist-editorial-html/SKILL.md` documents the house style and
`mcp_auditor/_theme.py` implements it. Nothing else enforces that relationship,
so this file does: the palette in the skill is parsed out of its fenced CSS
block and compared, hex for hex, with the palette the pages actually render.
Change one and this fails until you change the other.

The surface assertions guard the two things that are invisible until they are
missing: the paper grain (without it the cream reads as flat beige) and the one
font link (without it every page falls back to Courier).
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp_auditor import _theme
from mcp_auditor.atlas import load_atlas
from mcp_auditor.encyclopedia import build_encyclopedia
from mcp_auditor.htmlreport import render_html
from mcp_auditor.playground import build_playground
from mcp_auditor.rules import load_signatures
from mcp_auditor.types import AuditReport, Finding

SKILL = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "retro-futurist-editorial-html"
    / "SKILL.md"
)


def _documented_palette() -> dict[str, str]:
    """The palette as written in the skill's fenced ```css block."""
    text = SKILL.read_text(encoding="utf-8")
    blocks = re.findall(r"```css\n(.*?)```", text, re.DOTALL)
    palette_blocks = [b for b in blocks if "--cream:" in b]
    assert palette_blocks, "SKILL.md no longer documents a palette in a css block"
    return {
        name: value.lower()
        for name, value in re.findall(
            r"--([a-z][a-z-]*)\s*:\s*(#[0-9a-fA-F]{6})", palette_blocks[0]
        )
    }


def _report(findings: list[Finding] | None = None) -> AuditReport:
    return AuditReport(
        target="/tmp/example",
        is_mcp_server=True,
        tools_analyzed=1,
        score=40,
        findings=findings or [],
        generated_at="2026-07-07T00:00:00Z",
        signature_version=4,
    )


def _surfaces() -> dict[str, str]:
    return {
        "report": render_html(_report()),
        "encyclopedia": build_encyclopedia(load_atlas()),
        "playground": build_playground(load_signatures()),
    }


# --- palette -----------------------------------------------------------------


def test_palette_matches_the_documented_skill():
    assert _theme.PALETTE == _documented_palette()


def test_palette_has_no_extra_colours():
    """Thirteen names, no additions — a fourteenth colour has no documented job."""
    assert len(_theme.PALETTE) == 13


def test_tokens_css_emits_every_palette_colour_and_all_four_fonts():
    for name, value in _theme.PALETTE.items():
        assert f"--{name}: {value};" in _theme.THEME_TOKENS_CSS
    for family in ("Bungee", "Antonio", "Space Mono", "Major Mono Display"):
        assert family in _theme.THEME_TOKENS_CSS
    for token in ("--display", "--headline", "--mono", "--mojo"):
        assert f"{token}:" in _theme.THEME_TOKENS_CSS


def test_theme_commits_to_one_look():
    """No dark-mode fork: these pages are printed manuals, not dashboards."""
    assert "prefers-color-scheme" not in _theme.THEME_TOKENS_CSS


def test_fonts_link_requests_all_four_families_with_swap():
    for family in ("Bungee", "Antonio", "Space+Mono", "Major+Mono+Display"):
        assert f"family={family}" in _theme.FONTS_LINK
    assert "display=swap" in _theme.FONTS_LINK


def test_font_stacks_keep_a_real_offline_fallback():
    """The page has to survive being opened with no network."""
    for stack in _theme.FONT_STACKS.values():
        assert stack.count(",") >= 1


# --- severity ----------------------------------------------------------------


def test_severity_colours_are_palette_tokens():
    for severity, token in _theme.SEVERITY_COLORS.items():
        name = re.fullmatch(r"var\(--([a-z-]+)\)", token)
        assert name, f"{severity} is painted with a raw value: {token}"
        assert name.group(1) in _theme.PALETTE


def test_severity_never_rides_on_colour_alone():
    """Critical is a solid fill, high is an outline — fill separates them."""
    assert _theme.ATTENTION_SEVERITIES == ["critical", "high"]
    assert "background: var(--red)" in _theme.SEVERITY_CSS
    assert "color: var(--tangerine)" in _theme.SEVERITY_CSS
    for severity in ("critical", "high", "medium", "low", "info"):
        assert f".chip.{severity}" in _theme.SEVERITY_CSS


def test_severity_class_falls_back_to_info():
    assert _theme.severity_class("critical") == "critical"
    assert _theme.severity_class("nonsense") == "info"
    assert _theme.attention("critical") and not _theme.attention("low")


# --- every surface -----------------------------------------------------------


def test_every_surface_emits_the_grain_overlay():
    for name, page in _surfaces().items():
        assert 'class="grain"' in page, name
        assert 'class="stripes"' in page, name
        assert "feTurbulence" in page, name


def test_every_surface_links_the_one_font_sheet():
    for name, page in _surfaces().items():
        assert page.count("fonts.googleapis.com") == 1, name
        assert "family=Bungee" in page, name


def test_every_surface_is_printed_on_cream():
    for name, page in _surfaces().items():
        assert "#f4ead5" in page, name
        assert "background: var(--cream)" in page, name


def test_no_surface_rounds_a_primary_block():
    """Sharp corners everywhere. The circular icon badge is the one exception."""
    for name, page in _surfaces().items():
        radii = set(re.findall(r"border-radius:\s*([^;}]+)", page))
        assert radii <= {"0", "50%"}, f"{name}: {sorted(radii)}"


def test_no_surface_reaches_for_a_colour_outside_the_palette():
    allowed = {value.lower() for value in _theme.PALETTE.values()}
    for name, page in _surfaces().items():
        used = {h.lower() for h in re.findall(r"#[0-9a-fA-F]{6}\b", page)}
        assert used <= allowed, f"{name}: {sorted(used - allowed)}"
