"""Shared visual identity for every HTML surface (report, playground, encyclopedia).

One source of truth for the palette, the four type families and the component
CSS, so the surfaces cannot drift apart — which they had: the encyclopedia had
grown its own sixteen-colour palette and shared nothing with the dashboard.

The system is **Retro-Futurist Editorial**: warm cream paper, heavy warm-black
ink, hard offset shadows with zero blur, square corners, display type against
technical mono. It is specified in
``skills/retro-futurist-editorial-html/SKILL.md`` and ``tests/test_theme.py``
asserts the hexes below still match that document, so the skill and the product
move together or not at all.

Why paper and not another dark dashboard: these pages are read once, slowly, by
a person deciding whether to let someone else's code near their data. That is a
printed-manual reading, not a monitoring reading. So the page commits to one
look — there is no ``prefers-color-scheme`` fork here on purpose. A security
report that renders two different ways is a report whose screenshot cannot be
compared with the one in the ticket, and every severity mark below was measured
against cream, not against both.

Severity still never rides on colour alone. Every mark carries its written
label; ``critical`` is a solid ``--red`` fill, ``high`` an outlined
``--tangerine``, and everything below is ink separated by weight, fill and
outline. ``--orange`` is the structural accent — it edges cards, numbers
sections and rules the footer — which is exactly why it is deliberately *not* a
severity: a hue that touches every heading on the page cannot also mean *act
now*. ``--multipass-green`` is likewise reserved: it means *this is the safe
pattern*, so it marks the fix line and the safer-example block and nothing else.
"""

from __future__ import annotations

# --- palette -----------------------------------------------------------------

# The thirteen colours, exactly as specified in the skill. No additions: a
# fourteenth colour is a decision to make somewhere, and this page has no room
# for a hue whose meaning has to be explained.
PALETTE: dict[str, str] = {
    "cream": "#f4ead5",
    "cream-deep": "#e8dcb8",
    "paper": "#fff6e0",
    "ink": "#1a1410",
    "ink-soft": "#3a2a1c",
    "orange": "#ff6a1a",
    "tangerine": "#ff4d00",
    "amber": "#f5a623",
    "mondo": "#c89b3c",
    "diva": "#0066b3",
    "diva-deep": "#003a6b",
    "multipass-green": "#6fbf3a",
    "red": "#d6322c",
}

# Four families, no substitutions. Every stack keeps a real fallback, because
# these pages are opened from CI artifacts and airgapped laptops where the one
# Google Fonts request never resolves — the layout has to survive that.
FONT_STACKS: dict[str, str] = {
    "display": "'Bungee', 'Impact', sans-serif",
    "headline": "'Antonio', 'Helvetica Neue Condensed', 'Arial Narrow', sans-serif",
    "mono": "'Space Mono', 'Courier New', monospace",
    "mojo": "'Major Mono Display', 'Courier New', monospace",
}

# The single external asset any of these pages is allowed to reference.
FONTS_LINK = (
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2'
    "?family=Bungee"
    "&family=Antonio:wght@400;600;700"
    "&family=Space+Mono:ital,wght@0,400;0,700;1,400"
    "&family=Major+Mono+Display"
    '&display=swap">'
)

# Design tokens, generated from the dicts above so a palette edit cannot reach
# the CSS without also reaching the test that guards it.
THEME_TOKENS_CSS = (
    ":root {\n"
    + "\n".join(f"  --{name}: {value};" for name, value in PALETTE.items())
    + "\n\n"
    + "\n".join(f"  --{name}: {stack};" for name, stack in FONT_STACKS.items())
    + "\n}"
)

# --- atmosphere --------------------------------------------------------------

# Component 7. Never skipped: without the noise and the diagonal rule the cream
# reads as flat beige #f4ead5 rather than as paper, and the whole system with
# it. Both layers are fixed, inert and non-interactive.
ATMOSPHERE_CSS = """
.grain, .stripes { position: fixed; inset: 0; pointer-events: none; z-index: 9999; }
.grain {
  opacity: .55; mix-blend-mode: multiply;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='140' height='140' filter='url(%23n)' opacity='.42'/%3E%3C/svg%3E");
}
.stripes {
  opacity: .022;
  background-image: repeating-linear-gradient(45deg, var(--ink) 0 2px, transparent 2px 11px);
}
@media print { .grain, .stripes { display: none; } }
"""

# The two divs that carry it. Every page emits these immediately after <body>.
ATMOSPHERE_HTML = (
    '<div class="grain" aria-hidden="true"></div>'
    '<div class="stripes" aria-hidden="true"></div>'
)

# --- base --------------------------------------------------------------------

BASE_CSS = """
* { box-sizing: border-box; margin: 0; }
html { -webkit-text-size-adjust: 100%; }

body {
  background: var(--cream);
  color: var(--ink-soft);
  font: 14.5px/1.65 var(--mono);
  padding: 0 0 64px;
  /* The one permitted gradient: a faint vignette so the paper has a centre. */
  background-image: radial-gradient(circle at 50% 0%, rgba(255,246,224,.85), transparent 60%);
}

.wrap { max-width: 1200px; margin: 0 auto; padding: 0 28px; }

h1 {
  font-family: var(--display); font-size: clamp(42px, 7vw, 84px);
  line-height: .95; letter-spacing: -1px; text-transform: uppercase; color: var(--ink);
}
h2 {
  font-family: var(--display); font-size: clamp(26px, 3.4vw, 40px);
  line-height: 1; letter-spacing: -.5px; text-transform: uppercase; color: var(--ink);
}
h3 {
  font-family: var(--display); font-size: 17px; line-height: 1.15;
  text-transform: uppercase; color: var(--ink);
}
h4 {
  font-family: var(--headline); font-size: 13px; text-transform: uppercase;
  letter-spacing: 3px; color: var(--ink-soft);
}
.subtitle {
  font-family: var(--headline); font-size: clamp(20px, 2.6vw, 30px);
  letter-spacing: 3px; text-transform: uppercase; color: var(--diva);
  word-break: break-word;
}
.tagline {
  font-family: var(--headline); font-size: 18px; letter-spacing: 2px;
  text-transform: uppercase; color: var(--ink-soft);
}
.label {
  font-family: var(--headline); font-size: 12px; letter-spacing: 4px;
  text-transform: uppercase; color: var(--ink-soft);
}
code, .mono { font-family: var(--mono); }
.mojo { font-family: var(--mojo); letter-spacing: 1px; }

a { color: var(--diva); text-decoration-thickness: 2px; text-underline-offset: 3px; }
a:hover { color: var(--tangerine); }

p + p, p + ul, ul + p, p + ol { margin-top: 10px; }

ul.glyph { list-style: none; padding: 0; }
ul.glyph > li { padding-left: 20px; position: relative; margin: 4px 0; }
ul.glyph > li::before { content: '\\25B8'; position: absolute; left: 0; color: var(--orange); }

hr.rule { border: 0; border-top: 3px dashed var(--mondo); margin: 56px 0; }

.section { margin: 56px 0 0; }
"""

# --- signature components ----------------------------------------------------

# Components 1-6 from the kit, verbatim in behaviour. Component 7 (the grain)
# lives in ATMOSPHERE_CSS above because every page has to emit its markup too.
COMPONENTS_CSS = """
/* 1. OFFSET SHADOW BLOCK — the visual signature. */
.block {
  position: relative;
  background: var(--paper);
  border: 3px solid var(--ink);
  box-shadow: 6px 6px 0 var(--orange);
  border-radius: 0;
  padding: 22px 24px;
  transition: transform .2s ease, box-shadow .2s ease;
}
.block:hover { transform: translate(-2px, -2px); box-shadow: 8px 8px 0 var(--ink); }

/* Rhythm across a card group: orange, diva, mondo. */
.deck { display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
.deck > .block:nth-child(3n+1) { box-shadow: 6px 6px 0 var(--orange); }
.deck > .block:nth-child(3n+2) { box-shadow: 6px 6px 0 var(--diva); }
.deck > .block:nth-child(3n+3) { box-shadow: 6px 6px 0 var(--mondo); }

/* 2. LABELLED CONTAINER — a filing tag riding the top-left border. */
.labelled { position: relative; margin-top: 22px; }
.labelled::before {
  content: attr(data-label);
  position: absolute; top: -14px; left: 24px;
  background: var(--ink); color: var(--amber);
  padding: 4px 14px;
  font-family: var(--display); font-size: 13px; letter-spacing: 4px;
  white-space: nowrap;
}

/* 3. TIER BANNER — chapter break. */
.tier {
  display: grid; grid-template-columns: 100px 1fr 100px;
  border: 4px solid var(--ink); box-shadow: 8px 8px 0 var(--ink);
  margin: 56px 0 32px; min-height: 118px;
}
.tier > .num {
  display: grid; place-items: center;
  background: var(--orange); color: var(--ink);
  font-family: var(--display); font-size: 56px; line-height: 1;
  border-right: 4px solid var(--ink);
}
.tier > .body { background: var(--paper); padding: 18px 22px; }
.tier > .body .label { display: block; margin-bottom: 6px; }
.tier > .body h2 { margin-bottom: 6px; }
.tier > .stripe {
  display: grid; place-items: center; text-align: center;
  background: var(--diva); color: var(--paper);
  border-left: 4px solid var(--ink);
  font-family: var(--display); font-size: 11px; letter-spacing: 3px;
  padding: 8px 4px;
}
.tier.tier-2 > .num { background: var(--diva); color: var(--paper); }
.tier.tier-2 > .stripe { background: var(--mondo); color: var(--ink); }
.tier.tier-3 > .num { background: var(--mondo); color: var(--ink); }
.tier.tier-3 > .stripe { background: var(--orange); color: var(--ink); }

/* 4. PROMPT / CODE BLOCK. */
.prompt {
  position: relative;
  background: var(--ink); color: var(--cream);
  border-left: 6px solid var(--orange);
  box-shadow: 5px 5px 0 var(--orange);
  padding: 20px 24px 20px 28px;
  font-family: var(--mono); font-size: 13px; line-height: 1.6;
  white-space: pre-wrap; overflow-x: auto; word-break: break-word;
  margin-top: 22px;
}
.prompt::before {
  content: attr(data-tag);
  position: absolute; top: -14px; left: 22px;
  background: var(--ink); color: var(--amber);
  padding: 4px 14px;
  font-family: var(--display); font-size: 13px; letter-spacing: 4px;
}
.prompt.good { border-left-color: var(--multipass-green); box-shadow: 5px 5px 0 var(--multipass-green); }
.prompt.bad  { border-left-color: var(--red);             box-shadow: 5px 5px 0 var(--red); }

/* 5. CIRCULAR ICON BADGE — the one place a radius is allowed. */
.callout { position: relative; }
.callout::before {
  content: attr(data-glyph);
  position: absolute; top: -14px; left: -14px;
  width: 28px; height: 28px; border-radius: 50%;
  display: grid; place-items: center;
  background: var(--ink); color: var(--amber);
  font-family: var(--display); font-size: 13px;
}

/* 6. STAMPED FOOTER. */
.stamped {
  background: var(--ink); color: var(--cream);
  border: 4px solid var(--ink); box-shadow: 8px 8px 0 var(--orange);
  padding: 40px 32px; margin-top: 64px;
  display: flex; align-items: center; justify-content: space-between;
  gap: 24px; flex-wrap: wrap;
}
.stamped h2 { color: var(--orange); }
.stamped .meta { color: var(--cream-deep); font-size: 12px; margin-top: 8px; }
.stamp {
  transform: rotate(-2deg);
  border: 3px solid var(--multipass-green); color: var(--multipass-green);
  font-family: var(--display); font-size: 13px; letter-spacing: 3px;
  padding: 10px 18px; white-space: nowrap;
}

@media (max-width: 760px) {
  .deck { grid-template-columns: 1fr; }
  .tier { grid-template-columns: 1fr; }
  .tier > .num { border-right: 0; border-bottom: 4px solid var(--ink); padding: 12px; }
  .tier > .stripe { border-left: 0; border-top: 4px solid var(--ink); padding: 10px; }
  .wrap { padding: 0 20px; }
}
"""

# --- severity ----------------------------------------------------------------

# The severities that earn an alarm colour. A list rather than a set so it
# serializes straight into the playground's inline JS.
ATTENTION_SEVERITIES = ["critical", "high"]

# Severity -> the token that paints it. Values are CSS variables rather than
# hexes so a severity can never disagree with the palette above.
SEVERITY_COLORS = {
    "critical": "var(--red)",
    "high": "var(--tangerine)",
    "medium": "var(--ink)",
    "low": "var(--ink-soft)",
    "info": "var(--ink-soft)",
}

# Severity marks, shared verbatim by every surface. Kept here rather than copied
# into each one because that copying is exactly how the encyclopedia drifted.
#
# Three tiers, told apart by fill before hue: solid red (critical), outlined
# tangerine (high), ink on cream (everything else). `.dot` reinforces the tier
# next to a written label; it never carries the meaning by itself.
SEVERITY_CSS = """
.chip {
  display: inline-block;
  font-family: var(--display); font-size: 10px; letter-spacing: 2px;
  text-transform: uppercase; padding: 4px 9px; border-radius: 0;
  border: 2px solid var(--ink); background: var(--cream-deep); color: var(--ink);
}
.chip.critical { background: var(--red); color: var(--paper); border-color: var(--ink); }
.chip.high { background: var(--paper); color: var(--tangerine); border-color: var(--tangerine); }
.chip.medium { background: var(--cream-deep); color: var(--ink); }
.chip.low { background: var(--cream); color: var(--ink-soft); }
.chip.info { background: var(--cream); color: var(--ink-soft); border-color: var(--ink-soft); }

.dot {
  width: 11px; height: 11px; display: inline-block; flex: none;
  border: 2px solid var(--ink); background: var(--cream); border-radius: 0;
}
.dot.critical { background: var(--red); }
.dot.high { background: var(--paper); border-color: var(--tangerine); }
.dot.medium { background: var(--ink); }
.dot.low { background: var(--cream-deep); }
.dot.info { background: var(--cream); border-color: var(--ink-soft); }
"""

# Everything a page needs before its own page-specific rules.
PAGE_CSS = THEME_TOKENS_CSS + ATMOSPHERE_CSS + BASE_CSS + COMPONENTS_CSS + SEVERITY_CSS


def page_head(title: str, extra_css: str = "") -> str:
    """The complete `<head>` for a generated page.

    Every surface goes through here so none of them can quietly acquire a
    different font link, drop the viewport meta, or reorder the cascade.
    `extra_css` is the page's own layout, appended after the shared system.
    """
    return f"""<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
{FONTS_LINK}
<style>{PAGE_CSS}{extra_css}</style>
</head>"""


def severity_class(severity: str) -> str:
    """The marker class for a severity, so callers stop hand-writing them."""
    return severity if severity in SEVERITY_COLORS else "info"


def attention(severity: str) -> bool:
    """Whether this severity is one of the two that earn an alarm colour."""
    return severity in ATTENTION_SEVERITIES
