"""Shared visual identity for every HTML surface (report, playground, encyclopedia).

One source of truth for the CSS design tokens and the severity mapping, so the
surfaces cannot drift apart — which they had: the encyclopedia had grown its own
sixteen-colour palette and shared nothing with the dashboard.

**Three colours: black, white, and one orange.** Orange means exactly one thing —
this needs your attention — so it marks critical and high findings and nothing
else. Everything below that is ink, separated by label, weight and outline rather
than by hue. A page where only the real problems carry colour can be triaged at a
glance; a page where five severities each own a colour is just decorated, and the
eye has nowhere to land.

Severity therefore never rides on colour alone here — it never did, since every
mark carries its text label, but with two severities sharing one hue the label is
load-bearing rather than confirmatory. Critical and high are told apart by fill:
critical is solid, high is outlined.

Both oranges are measured, not chosen by eye. `#c2410c` holds at least 4.5:1 as
text on every light surface below and 5.18:1 under white for a filled chip;
`#e86a10` does the same on the dark ones. Each also sits inside its own mode's
OKLCH lightness band (light 0.43–0.77, dark 0.48–0.67) with chroma well clear of
the floor where a hue starts reading as grey.
"""

from __future__ import annotations

# The severities that earn the orange. A list rather than a set so it serializes
# straight into the playground's inline JS.
ATTENTION_SEVERITIES = ["critical", "high"]

# Severity -> the token that paints it. Values are CSS variables rather than
# hexes so a severity follows the active theme; the old fixed hexes rendered the
# same in dark mode, where they were tuned for light.
SEVERITY_COLORS = {
    "critical": "var(--accent)",
    "high": "var(--accent)",
    "medium": "var(--ink-2)",
    "low": "var(--ink-2)",
    "info": "var(--muted)",
}

# Design tokens. The exact `:root {\n...\n}` formatting is load-bearing: the
# artifact build step regex-extracts these blocks to add data-theme overrides.
THEME_TOKENS_CSS = """\
:root {
  --surface: #fcfcfb; --plane: #f9f9f7; --ink: #0b0b0b; --ink-2: #52514e;
  --muted: #898781; --grid: #e1e0d9; --border: rgba(11,11,11,0.10);
  --accent: #c2410c; --accent-ink: #ffffff; --accent-soft: rgba(194,65,12,0.10);
  --code-bg: #f0efec;
}
@media (prefers-color-scheme: dark) {
  :root {
    --surface: #1a1a19; --plane: #0d0d0d; --ink: #ffffff; --ink-2: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --border: rgba(255,255,255,0.10);
    --accent: #e86a10; --accent-ink: #0b0b0b; --accent-soft: rgba(232,106,16,0.16);
    --code-bg: #232322;
  }
}"""

# Severity marks, shared verbatim by every surface. Kept here rather than copied
# into each one because that copying is exactly how the encyclopedia drifted.
#
# Three tiers out of one hue: solid orange (critical), outlined orange (high),
# outlined ink (everything else). `.dot` reinforces the tier next to a written
# label; it never carries the meaning by itself.
SEVERITY_CSS = """
.chip {
  font-size: 11px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
  padding: 2px 8px; border-radius: 99px;
  background: none; color: var(--ink-2); box-shadow: inset 0 0 0 1px var(--border);
}
.chip.critical { background: var(--accent); color: var(--accent-ink); box-shadow: none; }
.chip.high { color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); }
.dot {
  width: 8px; height: 8px; border-radius: 50%; display: inline-block;
  background: var(--ink-2);
}
.dot.critical { background: var(--accent); }
.dot.high { background: var(--accent-soft); box-shadow: inset 0 0 0 2px var(--accent); }
.dot.info { background: var(--muted); }
"""


def severity_class(severity: str) -> str:
    """The marker class for a severity, so callers stop hand-writing them."""
    return severity if severity in SEVERITY_COLORS else "info"


def attention(severity: str) -> bool:
    """Whether this severity is one of the two that earn the orange."""
    return severity in ATTENTION_SEVERITIES
