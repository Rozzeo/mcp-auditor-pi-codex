"""Shared visual identity for every HTML surface (report, playground).

One source of truth for the CSS design tokens and the severity color mapping,
so the dashboard and the playground cannot drift apart. Colors follow the
validated reference dataviz palette: status colors for severity (always paired
with a text label — never color alone), blue for accent/magnitude.
"""

from __future__ import annotations

# Status palette (validated for both light and dark surfaces).
SEVERITY_COLORS = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#2a78d6",
    "info": "#898781",
}

# Design tokens. The exact `:root {\n...\n}` formatting is load-bearing: the
# artifact build step regex-extracts these blocks to add data-theme overrides.
THEME_TOKENS_CSS = """\
:root {
  --surface: #fcfcfb; --plane: #f9f9f7; --ink: #0b0b0b; --ink-2: #52514e;
  --muted: #898781; --grid: #e1e0d9; --border: rgba(11,11,11,0.10);
  --good: #0ca30c; --warn: #fab219; --crit: #d03b3b; --accent: #2a78d6;
  --code-bg: #f0efec;
}
@media (prefers-color-scheme: dark) {
  :root {
    --surface: #1a1a19; --plane: #0d0d0d; --ink: #ffffff; --ink-2: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --border: rgba(255,255,255,0.10);
    --accent: #3987e5; --code-bg: #232322;
  }
}"""
