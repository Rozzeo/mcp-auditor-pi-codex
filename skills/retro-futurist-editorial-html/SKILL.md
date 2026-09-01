---
name: retro-futurist-editorial-html
description: Build or restyle an HTML page in the Retro-Futurist Editorial house style — warm cream paper, heavy black ink, hard offset shadows, Bungee display type. Use for any user-facing HTML this project generates (audit report, Threat Encyclopedia, playground) and for any new standalone page, unless the user asks for a different visual system.
---

# Retro-Futurist Editorial

A printed manual from a 24th-century federation. Warm cream instead of cold
black. Heavy ink, thick borders, hard offset shadows with **zero blur**. Bold
display type against technical mono. Confident, structured, slightly playful,
never sterile.

Aesthetic neighbours: editorial poster design, Mœbius, Wes Anderson title cards,
ISOTYPE infographics, 90s sci-fi UI.

**Not** this: glassmorphism, neon cyberpunk, pastel gradients, dark-mode
dashboards, purple-on-white AI slop.

The point of the system is that two pages built from it, opened in two tabs,
read instantly as one series. Treat the rules below as load-bearing.

## Palette — exact, no additions

```css
--cream:#f4ead5;  --cream-deep:#e8dcb8;  --paper:#fff6e0;
--ink:#1a1410;    --ink-soft:#3a2a1c;
--orange:#ff6a1a; --tangerine:#ff4d00;   --amber:#f5a623;  --mondo:#c89b3c;
--diva:#0066b3;   --diva-deep:#003a6b;
--multipass-green:#6fbf3a;  --red:#d6322c;
```

- `--cream` is the page background. Always.
- `--ink` is text and borders. Always. It is warm near-black, never `#000`.
- `--orange` is the workhorse accent (~60% of accent usage);
  `--diva` is secondary (~30%).
- `--amber`, `--mondo`, `--multipass-green`, `--red` are reserved for their
  semantic roles: highlight, secondary rule, good, bad.
- No gradients except a faint radial vignette for atmosphere.
- **No shadow ever has blur.** Shadows are hard and offset.
- `border-radius` is `0` on every primary block. The only exception is the
  circular icon badge.

## Type — exact, four families

One Google Fonts `<link>`, four families, no substitutions:

| Token | Family | Used for |
|---|---|---|
| `--display` | `'Bungee'` | headlines, section numbers, badges, tier banners |
| `--headline` | `'Antonio'` | subtitles, taglines, metadata labels |
| `--mono` | `'Space Mono'` | body text, code, technical detail, captions |
| `--mojo` | `'Major Mono Display'` | rare accent labels only |

```
H1        clamp(42px, 7vw, 84px)   --display   line-height .95
H2        clamp(26px, 3.4vw, 40px) --display   line-height 1
Subtitle  clamp(20px, 2.6vw, 30px) --headline  letter-spacing 3px
Tagline   18px  --headline  all-caps  letter-spacing 2px
Body      14.5px --mono  line-height 1.65
Caption   11–13px
```

Headings all-caps, body sentence-case. Tight tracking on display (−1px…0),
wide on labels (2–4px). Never Inter, Roboto, Arial, Space Grotesk, or a system
font stack.

## Signature components

Copy the implementations from
[`references/kit.css`](references/kit.css) rather than re-deriving them.

1. **Offset shadow block** — the visual signature. `--paper` fill, 3px ink
   border, `box-shadow: 6px 6px 0 <accent>`. On hover: `translate(-2px,-2px)`
   and the shadow grows to 8px on both axes, 0.2s ease. Rotate the shadow
   colour across a card group: orange, diva, mondo.
2. **Labelled container** — a small tag riding the top-left border like a
   filing label: `::before`, ink background, amber `--display` text, 13px,
   4px tracking, `top:-14px; left:24px`.
3. **Tier banner** — chapter break. `100px 1fr 100px` grid: solid accent number
   cell (`--display`, 56px), paper body with label + title + tagline, solid
   vertical stripe label on the right. 4px ink border, 8px ink offset shadow.
4. **Prompt / code block** — ink background, cream text, 6px coloured left
   border, matching 5px offset shadow, floating `data-tag` label.
   `.good` → multipass-green, `.bad` → red.
5. **Circular icon badge** — 28px ink circle at `top:-14px; left:-14px` of a
   callout, one amber glyph (`!`, `★`, `◉`). 50% radius — the one exception.
6. **Stamped footer** — dark closing block, big display headline in
   orange/amber, plus a `rotate(-2deg)` multipass-green stamp reading
   `TRANSMISSION COMPLETE` or an equivalent.
7. **Paper grain overlay** — **never skip this.** Two fixed, full-screen,
   `pointer-events:none` layers: an inline-SVG noise filter at `opacity:.55;
   mix-blend-mode:multiply`, and 45° diagonal stripes at ~2.2% opacity. Without
   them the cream reads flat and digital.

## Layout

Content max-width 1200px, centered, 28–32px side padding. 56–64px between major
sections. Card grids `auto-fit` at 320px minimum with 18px gaps. Two-column
compare blocks for bad-vs-good. Below 760px every grid and banner collapses to
one column, keeping a readable order.

## Motion

Restrained — this is editorial design, not a dashboard.

- Card hover: `translate(-2px,-2px)`, shadow +2px each axis, 0.2s ease.
- Pulse only on live status dots (1.6s ease-in-out infinite).
- No scroll animation, no parallax, no fade-in on load.
- At most one hero moment: a staggered header reveal over the first 800ms.

## Voice

- Section taglines all-caps, technical-poetic:
  `DIMENSION CALLOUTS THAT CAN'T BE MISREAD`.
- Body prose: confident, second person, short sentences. No "let me explain",
  no "in conclusion", no corporate hedging.
- `//` before structural labels: `// MAPPING 01`.
- `▸` as the inline bullet glyph. `★` and `◉` as ornaments.
- Wink at the source material once or twice at most — a wink, never a costume.

## Colour still has to carry meaning

This project's pages are security surfaces, so the palette does semantic work
and must survive that:

- **Severity is never encoded by colour alone.** Every mark carries its text
  label. `critical` fills solid `--red`; `high` is outlined `--tangerine`;
  everything below is ink, separated by weight and outline.
- `--multipass-green` means *this is the safe pattern* and nothing else.
- `--orange` is structure and emphasis — it is not a severity.
- Body text is `--ink-soft` on `--paper` or `--cream`; both clear 4.5:1.
  Never put `--amber` or `--mondo` on cream as body text.

## Output

One self-contained `.html` file: all CSS in a single `<style>` in `<head>`, one
Google Fonts `<link>`, vanilla HTML/CSS plus minimal vanilla JS only where an
interaction needs it. No build step, no Tailwind, no external CSS. It must open
correctly straight from disk.

## Before you call it done

Open it next to another page from this system. If they do not read as siblings,
revise. Check specifically: cream field present, grain overlay present, every
corner sharp, every shadow blur-free, all four fonts loading, no colour outside
the palette.

## Where this lives in the product

`mcp_auditor/_theme.py` is the single source of truth for the generated pages —
the palette, the fonts, and the component CSS live there as Python constants and
are shared by `htmlreport.py`, `encyclopedia.py`, and `playground.py`.
`tests/test_theme.py` asserts the hexes in `_theme.py` still match the palette
documented above, so the skill and the product cannot drift apart. Change both
or neither.
