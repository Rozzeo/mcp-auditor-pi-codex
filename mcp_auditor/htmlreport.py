"""Self-contained HTML dashboard for an AuditReport (spec §8, presentation only).

`render_html(report)` returns one standalone HTML document — no external assets
beyond a single font link, no scripts required to read it — so a report can be
attached to a ticket, mailed to a security reviewer, or opened from CI
artifacts. Carries no detection logic.

The visual system is Retro-Futurist Editorial, and it lives in `_theme`: cream
paper, ink borders, hard offset shadows. The score is the page's chapter heading
because it is the one thing a reader looks for first; every finding below it is
an offset-shadow block whose shadow turns red only when the severity earns it.
Severity is never encoded by colour alone — every mark carries its text label.
"""

from __future__ import annotations

import html
from collections import Counter

from ._theme import ATMOSPHERE_HTML, attention, page_head, severity_class
from .types import SEVERITY_ORDER, AuditReport

# Page-specific layout. Everything shared — tokens, atmosphere, type scale, the
# seven components, the severity marks — arrives from `page_head`.
_CSS = """
.masthead { padding: 56px 0 8px; }
.masthead h1 { margin-bottom: 6px; }
.masthead .subtitle { color: var(--diva-deep); }
.lede { max-width: 760px; margin-top: 12px; color: var(--ink-soft); }
.meta { font-family: var(--mono); font-size: 12px; color: var(--ink-soft); }

/* Score hero — the tier banner, used as the page's chapter heading. */
.tier.hero { grid-template-columns: 150px 1fr 120px; margin-top: 40px; }
.tier.hero > .num { font-size: 46px; letter-spacing: -1px; }
.tier.hero > .num small { display: block; font-size: 14px; letter-spacing: 1px; }
.tier.hero > .num .withheld { font-size: 15px; letter-spacing: 2px; text-align: center; }
.meter { height: 14px; border: 3px solid var(--ink); background: var(--cream-deep); margin-top: 14px; }
.meter > i { display: block; height: 100%; }

/* Severity tiles. */
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(148px, 1fr)); gap: 14px; margin-top: 20px; }
.tile {
  background: var(--paper); border: 3px solid var(--ink);
  box-shadow: 5px 5px 0 var(--ink); padding: 12px 14px;
}
.tile b { display: block; font-family: var(--display); font-size: 30px; line-height: 1; color: var(--ink); }
.tile span { display: flex; align-items: center; gap: 8px; margin-top: 8px;
  font-family: var(--headline); font-size: 12px; letter-spacing: 3px; text-transform: uppercase; }
.tile.critical.attention { box-shadow: 5px 5px 0 var(--red); }
.tile.high.attention { box-shadow: 5px 5px 0 var(--tangerine); }
.tile.empty { background: var(--cream); border-color: var(--ink-soft); box-shadow: none; }
.tile.empty b { color: var(--ink-soft); }

/* Findings by category — magnitude, not alarm. Every one of these is already a
   finding, so painting the bars red would spend the alarm colour on the least
   urgent thing on the page. Diva is structure. */
.bars { display: grid; gap: 10px; margin-top: 6px; }
.bar-row { display: grid; grid-template-columns: 190px 1fr 40px; gap: 12px; align-items: center; }
.bar-row .cat { font-family: var(--headline); font-size: 13px; letter-spacing: 2px;
  text-transform: uppercase; color: var(--ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bar-track { height: 16px; border: 2px solid var(--ink); background: var(--cream-deep); }
.bar-track > i { display: block; height: 100%; background: var(--diva); min-width: 3px; }
.bar-row .n { text-align: right; font-family: var(--display); font-size: 14px; color: var(--ink); }

/* Panels. */
.panel { margin-top: 34px; }
.panel.diva { box-shadow: 6px 6px 0 var(--diva); }
.panel.mondo { box-shadow: 6px 6px 0 var(--mondo); }
.panel.orange { box-shadow: 6px 6px 0 var(--orange); }
.cap-list { display: grid; gap: 12px; margin-top: 8px; }
.cap-row { display: grid; grid-template-columns: 200px 1fr; gap: 14px;
  padding-bottom: 10px; border-bottom: 2px dashed var(--cream-deep); }
.cap-row:last-child { border-bottom: 0; padding-bottom: 0; }
.cap-tool { font-family: var(--mono); font-weight: 700; color: var(--ink); word-break: break-all; }
.policy-decision { font-family: var(--display); font-size: clamp(26px, 3.4vw, 40px);
  line-height: 1; margin: 4px 0 10px; }
.policy-line { margin-top: 6px; }

/* Findings. */
.findings { display: grid; gap: 26px; margin-top: 30px; }
.findings > .finding:nth-child(3n+1) { box-shadow: 6px 6px 0 var(--orange); }
.findings > .finding:nth-child(3n+2) { box-shadow: 6px 6px 0 var(--diva); }
.findings > .finding:nth-child(3n+3) { box-shadow: 6px 6px 0 var(--mondo); }
.findings > .finding.critical { box-shadow: 6px 6px 0 var(--red); }
.findings > .finding.high { box-shadow: 6px 6px 0 var(--tangerine); }
.findings > .finding:hover { transform: translate(-2px, -2px); box-shadow: 8px 8px 0 var(--ink); }
.finding { padding: 26px 24px 24px; }
.top { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.rule-id { font-family: var(--mono); font-weight: 700; font-size: 13px; color: var(--ink); }
.badge {
  font-family: var(--headline); font-size: 11px; letter-spacing: 2px; text-transform: uppercase;
  border: 2px solid var(--ink-soft); background: var(--cream); color: var(--ink-soft); padding: 1px 8px;
}
.loc { font-family: var(--mono); font-size: 12px; color: var(--ink-soft); word-break: break-all; }
.msg { font-family: var(--headline); font-size: 19px; line-height: 1.25; color: var(--ink); letter-spacing: .3px; }
.brief {
  position: relative; margin-top: 26px; padding: 16px 18px;
  background: var(--cream-deep); border: 3px solid var(--ink); box-shadow: 4px 4px 0 var(--mondo);
}
.brief h4 { margin-bottom: 6px; }
.fix {
  margin-top: 22px; padding: 12px 16px; background: var(--paper);
  border: 3px solid var(--ink); border-left: 6px solid var(--multipass-green);
  box-shadow: 4px 4px 0 var(--multipass-green);
}
.fix b { font-family: var(--display); font-size: 11px; letter-spacing: 3px; color: var(--ink); margin-right: 6px; }
.suppressed { opacity: .62; }
.suppressed .msg { text-decoration: line-through; }
.sup-note {
  font-family: var(--headline); font-size: 13px; letter-spacing: 2px; text-transform: uppercase;
  color: var(--ink); background: var(--cream-deep); border-left: 5px solid var(--mondo);
  padding: 6px 10px; margin-bottom: 12px;
}
/* Mondo, not green: green means *this is the safe pattern*, and an empty
   findings list is an absence of evidence, not an all-clear. */
.clean { margin-top: 30px; text-align: center; padding: 44px 24px; box-shadow: 6px 6px 0 var(--mondo); }
.clean h3 { margin-bottom: 10px; }

@media (max-width: 760px) {
  .tier.hero { grid-template-columns: 1fr; }
  .bar-row { grid-template-columns: 1fr 42px; }
  .bar-row .bar-track { grid-column: 1 / -1; }
  .cap-row { grid-template-columns: 1fr; }
}
"""


def _score_color(score: int) -> str:
    """Ink when nothing needs doing, red when something does.

    Two states rather than five: the verdict beneath the meter already separates
    "needs review" from "high risk", and a hue that means *attention* cannot also
    mean *slightly less attention* without turning into decoration.
    """
    return "var(--ink)" if score >= 80 else "var(--red)"


def _score_fill(score: int | None) -> tuple[str, str]:
    """(background, text) for the hero's number cell.

    The cell is 150px of solid colour at the top of the page, so it is the one
    place the score gets to raise its voice. Amber is *highlight*, red is *bad*;
    a clean score gets neither, because a green all-clear is a safety claim this
    tool does not make.
    """
    if score is None:
        return "var(--mondo)", "var(--ink)"
    if score >= 80:
        return "var(--cream-deep)", "var(--ink)"
    if score >= 50:
        return "var(--amber)", "var(--ink)"
    return "var(--red)", "var(--paper)"


def _verdict(score: int | None) -> str:
    if score is None:
        return "Withheld — analysis coverage is incomplete, so a numeric indicator would be misleading."
    if score >= 80:
        return "Low risk — review the findings below before installing."
    if score >= 50:
        return "Needs review — resolve the findings before connecting this server."
    return "High risk — do not connect this server to agents or internal data."


def _headline(score: int | None) -> str:
    """The verdict's first clause, promoted to the banner's headline."""
    return _verdict(score).split(" — ", 1)[0]


def _detail(score: int | None) -> str:
    """The verdict's second clause — what the reader should actually do.

    Recapitalised, because the banner reads it as its own sentence and the CSS
    that upper-cases it is not guaranteed to arrive.
    """
    parts = _verdict(score).split(" — ", 1)
    detail = parts[1] if len(parts) > 1 else parts[0]
    return detail[:1].upper() + detail[1:]


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def _tile_class(severity: str, count: int) -> str:
    """A zero count is greyed rather than coloured — nothing to attend to."""
    if count == 0:
        return " empty"
    return " attention" if attention(severity) else ""


def render_html(report: AuditReport) -> str:
    """Render the report as one standalone HTML document (a string)."""
    if not report.is_mcp_server:
        body = (
            '<div class="block labelled panel diva" data-label="Notice">'
            "<h3>Not an MCP server</h3>"
            f"<p class=\"lede\">{_esc(report.message or 'No MCP tool definitions found.')}</p></div>"
        )
        return _page(report, body)

    score = report.score
    summary = report.summary()
    active = [f for f in report.findings if not f.suppressed]

    tiles = "".join(
        f'<div class="tile {severity_class(sev)}{_tile_class(sev, summary[sev])}">'
        f"<b>{summary[sev]}</b>"
        f'<span><i class="dot {severity_class(sev)}"></i>{sev}</span></div>'
        for sev in SEVERITY_ORDER
    )

    cat_counts = Counter(f.category for f in active)
    max_n = max(cat_counts.values(), default=1)
    bars = "".join(
        f'<div class="bar-row"><span class="cat">{_esc(cat.replace("_", " "))}</span>'
        f'<span class="bar-track"><i style="width:{max(2, round(100 * n / max_n))}%"></i></span>'
        f'<span class="n">{n}</span></div>'
        for cat, n in cat_counts.most_common()
    )
    bars_card = (
        '<div class="block labelled panel mondo" data-label="Categories">'
        f'<div class="bars">{bars}</div></div>'
        if cat_counts
        else ""
    )
    capability_card = _capability_card(report)
    policy_card = _policy_card(report)
    flow_card = _flow_card(report)

    if report.findings:
        cards = "".join(_finding_card(f) for f in report.findings)
        findings_html = f'<div class="findings">{cards}</div>'
    else:
        findings_html = (
            '<div class="block clean"><h3>Nothing matched</h3>'
            '<p>No supported threat patterns were found in the analyzed surface. This is not a '
            "universal safety claim; review coverage and limitations.</p></div>"
        )

    fill, fill_ink = _score_fill(score)
    if score is None:
        score_value = '<span class="withheld">withheld</span>'
        meter = ""
    else:
        score_value = f"{score}<small>/100</small>"
        meter = (
            f'<div class="meter"><i style="width:{score}%;background:{_score_color(score)}"></i></div>'
        )

    body = f"""
<section class="tier hero">
  <div class="num" style="background:{fill};color:{fill_ink}">{score_value}</div>
  <div class="body">
    <span class="label">// Static risk indicator — not a safety verdict</span>
    <h2>{_esc(_headline(score))}</h2>
    <p class="tagline">{_esc(_detail(score))}</p>
    {meter}
  </div>
  <div class="stripe">Risk index</div>
</section>

<section class="section">
  <h2>Findings by severity</h2>
  <div class="tiles">{tiles}</div>
  <p class="meta" style="margin-top:16px">Tools analyzed: {report.tools_analyzed}
  · Active findings: {len(active)}</p>
</section>
{bars_card}
{capability_card}
{policy_card}
{flow_card}

<section class="section">
  <h2>Findings</h2>
  {findings_html}
</section>
"""
    return _page(report, body)


def _capability_card(report: AuditReport) -> str:
    rows = []
    for tool in report.tools or []:
        if not tool.capabilities and not tool.annotations:
            continue
        inferred = ", ".join(sorted({item.capability for item in tool.capabilities})) or "none observed"
        annotations = ", ".join(
            f"{key}={str(value).lower()}" for key, value in tool.annotations.items()
        ) or "none declared"
        rows.append(
            f'<div class="cap-row"><span class="cap-tool">{_esc(tool.name)}</span>'
            f'<span><b>Observed:</b> {_esc(inferred)}<br><b>Annotations:</b> {_esc(annotations)}</span></div>'
        )
    if not rows:
        return ""
    return (
        '<div class="block labelled panel diva" data-label="Capabilities">'
        "<h3>Observed tool capabilities</h3>"
        '<div class="cap-list">' + "".join(rows) + "</div></div>"
    )


def _policy_card(report: AuditReport) -> str:
    if not report.policy:
        return ""
    policy = report.policy
    decision = policy.get("decision", "manual_review")
    # Only `allow` needs nothing from the reader; the other two are the same
    # call to action, and the word beneath them says which one it is.
    color = "var(--ink)" if decision == "allow" else "var(--red)"
    identity = f"{policy.get('department')} / {policy.get('employee')}"
    if policy.get("agent"):
        identity += f" / {policy['agent']}"
    unclassified = policy.get("coverage", {}).get("unclassified_tools", [])
    manual = (
        f'<p class="policy-line"><b>Manual review:</b> implementation unavailable for {_esc(", ".join(unclassified))}</p>'
        if unclassified
        else ""
    )
    return f'''
<div class="block labelled panel mondo" data-label="Policy">
  <h3>Department privilege policy · {_esc(identity)}</h3>
  <div class="policy-decision" style="color:{color}">{_esc(str(decision).upper())}</div>
  <p class="policy-line"><b>Effective allow:</b> {_esc(", ".join(policy.get("effective_allow", [])) or "none")}</p>
  <p class="policy-line"><b>Requested:</b> {_esc(", ".join(policy.get("requested", [])) or "none observed")}</p>
  {manual}
</div>'''


def _flow_card(report: AuditReport) -> str:
    if not report.data_flows:
        return ""
    rows = []
    for flow in report.data_flows:
        rows.append(
            '<div class="cap-row">'
            f'<span class="cap-tool">{_esc(flow.get("source"))} → {_esc(flow.get("sink"))}</span>'
            f'<span><b>{_esc(flow.get("status", "POSSIBLE"))}</b><br>'
            f'{_esc(flow.get("source_evidence", {}).get("location", ""))} → '
            f'{_esc(flow.get("sink_evidence", {}).get("location", ""))}</span></div>'
        )
    return (
        '<div class="block labelled panel orange" data-label="Data flow">'
        "<h3>Sensitive data flows</h3>"
        '<p class="meta">A possible flow requires contextual review; it does not prove runtime transmission.</p>'
        f'<div class="cap-list">{"".join(rows)}</div></div>'
    )


def _finding_card(f) -> str:
    sev = severity_class(f.severity)
    flag = " attention" if attention(f.severity) else ""
    conf = f' <span class="badge">confidence: {_esc(f.confidence)}</span>' if f.confidence else ""
    threat = f' <span class="badge">{_esc(f.threat_id)}</span>' if f.threat_id else ""
    cite = ""
    for src in f.sources or []:
        if src.get("section"):
            arx = f" · arXiv:{_esc(src['arxiv'])}" if src.get("arxiv") else ""
            cite = f' <span class="badge">paper §{_esc(src["section"])}{arx}</span>'
            break
    evidence = (
        f'<div class="prompt" data-tag="Evidence">{_esc(f.evidence)}</div>' if f.evidence else ""
    )
    sup_cls = " suppressed" if f.suppressed else ""
    sup_note = (
        f'<div class="sup-note">Suppressed: {_esc(f.suppress_reason or "reviewed false positive")}</div>'
        if f.suppressed
        else ""
    )
    tool = f' <span class="badge">tool: {_esc(f.tool_name)}</span>' if f.tool_name else ""
    education = ""
    if f.education:
        questions = f.education.get("review_questions") or []
        verify = f"<p><b>Verify:</b> {_esc(questions[0])}</p>" if questions else ""
        education = (
            '<div class="brief callout" data-glyph="◉">'
            "<h4>What this means</h4>"
            f'<p>{_esc(f.education.get("summary", f.education.get("name", "")))}</p>'
            f"{verify}</div>"
        )
    label = _esc(str(f.category or "finding").replace("_", " "))
    return f"""
<article class="block labelled finding {sev}{flag}{sup_cls}" data-label="{label}">
  <div class="top">
    <span class="chip {sev}">{_esc(f.severity)}</span>
    <span class="rule-id">{_esc(f.id)}</span>{tool}{threat}{cite}{conf}
    <span class="loc">{_esc(f.location or "")}</span>
  </div>
  {sup_note}
  <div class="msg">{_esc(f.message)}</div>
  {evidence}
  {education}
  <div class="fix"><b>Fix:</b> {_esc(f.recommendation)}</div>
</article>"""


def _page(report: AuditReport, body: str) -> str:
    sig = (
        f" · signatures v{report.signature_version}"
        if report.signature_version is not None
        else ""
    )
    evidence_note = {
        "runtime": "Runtime evidence — discovery metadata was queried; business operations were not executed.",
        "declared": "Declared evidence — operation names came from documentation, not a deployed server.",
        "source": "Source evidence — the target was read as text and never executed.",
    }.get(report.evidence_type, f"Evidence: {report.evidence_type}")
    return f"""<!doctype html>
<html lang="en">
{page_head(f"mcp-audit · {_esc(report.target)}", _CSS)}
<body>
{ATMOSPHERE_HTML}
<div class="wrap">
<header class="masthead">
  <h1>mcp-audit</h1>
  <p class="subtitle">{_esc(report.target)}</p>
  <p class="lede">{_esc(evidence_note)}</p>
</header>
{body}
<footer class="stamped">
  <div>
    <h2>Transmission complete</h2>
    <p class="meta">Generated {_esc(report.generated_at)}{sig} · mcp-auditor</p>
  </div>
  <div class="stamp">Static analysis only</div>
</footer>
</div>
</body>
</html>
"""
