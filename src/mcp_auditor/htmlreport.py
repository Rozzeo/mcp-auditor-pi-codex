"""Self-contained HTML dashboard for an AuditReport (spec §8, presentation only).

`render_html(report)` returns one standalone HTML document — no external assets,
no scripts required to read it — so a report can be attached to a ticket, mailed
to a security reviewer, or opened from CI artifacts. Carries no detection logic.

Colors follow the validated reference dataviz palette (status colors for
severity, blue ramp for magnitude); severity is never encoded by color alone —
every mark carries a text label.
"""

from __future__ import annotations

import html
from collections import Counter

from ._theme import SEVERITY_COLORS as _SEV_COLOR
from ._theme import THEME_TOKENS_CSS
from .types import SEVERITY_ORDER, AuditReport

_CSS = THEME_TOKENS_CSS + """
* { box-sizing: border-box; margin: 0; }
body {
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
  background: var(--plane); color: var(--ink); padding: 32px 20px 64px;
}
.wrap { max-width: 980px; margin: 0 auto; }
header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 6px; }
header h1 { font-size: 20px; font-weight: 700; }
header .target { font-family: ui-monospace, monospace; font-size: 14px; color: var(--ink-2); word-break: break-all; }
.meta { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
.grid { display: grid; grid-template-columns: 260px 1fr; gap: 16px; margin-bottom: 16px; }
@media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 20px;
}
.card h2 { font-size: 12px; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); margin-bottom: 14px; }
.hero { font-size: 56px; font-weight: 700; line-height: 1; }
.hero small { font-size: 20px; font-weight: 500; color: var(--muted); }
.meter { height: 8px; border-radius: 4px; background: var(--grid); margin: 16px 0 8px; overflow: hidden; }
.meter > i { display: block; height: 100%; border-radius: 4px; }
.verdict { font-size: 13px; color: var(--ink-2); }
.tiles { display: flex; gap: 10px; flex-wrap: wrap; }
.tile {
  flex: 1 1 90px; border: 1px solid var(--border); border-radius: 10px;
  padding: 10px 12px; background: var(--surface);
}
.tile b { display: block; font-size: 24px; font-weight: 700; }
.tile span { font-size: 12px; color: var(--ink-2); display: inline-flex; align-items: center; gap: 6px; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.bars { display: grid; gap: 8px; }
.bar-row { display: grid; grid-template-columns: 170px 1fr 32px; gap: 10px; align-items: center; font-size: 13px; }
.bar-row .label { color: var(--ink-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bar-track { height: 14px; background: none; }
.bar-track > i { display: block; height: 100%; background: var(--accent); border-radius: 0 4px 4px 0; min-width: 2px; }
.bar-row .n { text-align: right; font-variant-numeric: tabular-nums; color: var(--ink-2); }
.findings { display: grid; gap: 12px; margin-top: 16px; }
.finding { border-left: 4px solid var(--grid); }
.finding .top { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.chip {
  font-size: 11px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
  padding: 2px 8px; border-radius: 99px; color: #fff;
}
.chip.info, .chip.medium { color: #1a1a19; }
.rule-id { font-family: ui-monospace, monospace; font-size: 13px; font-weight: 600; }
.loc { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); word-break: break-all; }
.badge { font-size: 11px; border: 1px solid var(--border); border-radius: 99px; padding: 2px 8px; color: var(--ink-2); }
.msg { font-size: 15px; margin-bottom: 8px; }
.evidence {
  font-family: ui-monospace, monospace; font-size: 12.5px; background: var(--code-bg);
  border-radius: 8px; padding: 8px 10px; margin-bottom: 8px; overflow-x: auto; white-space: pre-wrap;
  color: var(--ink-2);
}
.fix { font-size: 13px; color: var(--ink-2); }
.fix b { color: var(--good); font-weight: 600; }
.suppressed { opacity: .55; }
.suppressed .msg { text-decoration: line-through; }
.sup-note { font-size: 12px; font-style: italic; color: var(--muted); margin-bottom: 6px; }
.clean { text-align: center; padding: 40px 20px; color: var(--good); font-weight: 600; }
.cap-list { display: grid; gap: 10px; }
.cap-row { display: grid; grid-template-columns: 160px 1fr; gap: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
.cap-row:last-child { border-bottom: 0; padding-bottom: 0; }
.cap-tool { font-family: ui-monospace, monospace; font-weight: 600; }
.policy-decision { font-size: 22px; font-weight: 750; margin-bottom: 8px; }
.policy-line { font-size: 13px; color: var(--ink-2); margin-top: 5px; }
footer { margin-top: 32px; font-size: 12px; color: var(--muted); }
"""


def _score_color(score: int) -> str:
    if score >= 80:
        return "var(--good)"
    if score >= 50:
        return "var(--warn)"
    return "var(--crit)"


def _verdict(score: int) -> str:
    if score >= 80:
        return "Low risk — review the findings below before installing."
    if score >= 50:
        return "Needs review — resolve the findings before connecting this server."
    return "High risk — do not connect this server to agents or internal data."


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def render_html(report: AuditReport) -> str:
    """Render the report as one standalone HTML document (a string)."""
    if not report.is_mcp_server:
        body = (
            f'<div class="card"><h2>Not an MCP server</h2>'
            f"<p>{_esc(report.message or 'No MCP tool definitions found.')}</p></div>"
        )
        return _page(report, body)

    score = report.score if report.score is not None else 0
    color = _score_color(score)
    summary = report.summary()
    active = [f for f in report.findings if not f.suppressed]

    tiles = "".join(
        f'<div class="tile"><b>{summary[sev]}</b>'
        f'<span><i class="dot" style="background:{_SEV_COLOR[sev]}"></i>{sev}</span></div>'
        for sev in SEVERITY_ORDER
    )

    cat_counts = Counter(f.category for f in active)
    max_n = max(cat_counts.values(), default=1)
    bars = "".join(
        f'<div class="bar-row"><span class="label">{_esc(cat.replace("_", " "))}</span>'
        f'<span class="bar-track"><i style="width:{max(2, round(100 * n / max_n))}%"></i></span>'
        f'<span class="n">{n}</span></div>'
        for cat, n in cat_counts.most_common()
    )
    bars_card = (
        f'<div class="card"><h2>Findings by category</h2><div class="bars">{bars}</div></div>'
        if cat_counts
        else ""
    )
    capability_card = _capability_card(report)
    policy_card = _policy_card(report)

    if report.findings:
        cards = "".join(_finding_card(f) for f in report.findings)
        findings_html = f'<div class="findings">{cards}</div>'
    else:
        findings_html = '<div class="card clean">✓ No findings. This server looks clean.</div>'

    body = f"""
<div class="grid">
  <div class="card">
    <h2>Security score</h2>
    <div class="hero" style="color:{color}">{score}<small>/100</small></div>
    <div class="meter"><i style="width:{score}%;background:{color}"></i></div>
    <div class="verdict">{_verdict(score)}</div>
  </div>
  <div class="card">
    <h2>Findings by severity</h2>
    <div class="tiles">{tiles}</div>
    <p class="meta" style="margin:14px 0 0">Tools analyzed: {report.tools_analyzed}
    · Active findings: {len(active)}</p>
  </div>
</div>
{bars_card}
{capability_card}
{policy_card}
{findings_html}
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
    return '<div class="card" style="margin-bottom:16px"><h2>Observed tool capabilities</h2><div class="cap-list">' + "".join(rows) + "</div></div>"


def _policy_card(report: AuditReport) -> str:
    if not report.policy:
        return ""
    policy = report.policy
    decision = policy.get("decision", "manual_review")
    color = {"allow": "var(--good)", "deny": "var(--crit)", "manual_review": "var(--warn)"}.get(
        decision, "var(--warn)"
    )
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
<div class="card" style="margin-bottom:16px">
  <h2>Department privilege policy · {_esc(identity)}</h2>
  <div class="policy-decision" style="color:{color}">{_esc(str(decision).upper())}</div>
  <p class="policy-line"><b>Effective allow:</b> {_esc(", ".join(policy.get("effective_allow", [])) or "none")}</p>
  <p class="policy-line"><b>Requested:</b> {_esc(", ".join(policy.get("requested", [])) or "none observed")}</p>
  {manual}
</div>'''


def _finding_card(f) -> str:
    sev_color = _SEV_COLOR.get(f.severity, "var(--muted)")
    conf = f' <span class="badge">confidence: {_esc(f.confidence)}</span>' if f.confidence else ""
    threat = f' <span class="badge">{_esc(f.threat_id)}</span>' if f.threat_id else ""
    cite = ""
    for src in f.sources or []:
        if src.get("section"):
            arx = f" · arXiv:{_esc(src['arxiv'])}" if src.get("arxiv") else ""
            cite = f' <span class="badge">paper §{_esc(src["section"])}{arx}</span>'
            break
    evidence = f'<div class="evidence">{_esc(f.evidence)}</div>' if f.evidence else ""
    sup_cls = " suppressed" if f.suppressed else ""
    sup_note = (
        f'<div class="sup-note">Suppressed: {_esc(f.suppress_reason or "reviewed false positive")}</div>'
        if f.suppressed
        else ""
    )
    tool = f' <span class="badge">tool: {_esc(f.tool_name)}</span>' if f.tool_name else ""
    return f"""
<div class="card finding{sup_cls}" style="border-left-color:{sev_color}">
  <div class="top">
    <span class="chip {f.severity}" style="background:{sev_color}">{_esc(f.severity)}</span>
    <span class="rule-id">{_esc(f.id)}</span>{tool}{threat}{cite}{conf}
    <span class="loc">{_esc(f.location or "")}</span>
  </div>
  {sup_note}
  <div class="msg">{_esc(f.message)}</div>
  {evidence}
  <div class="fix"><b>Fix:</b> {_esc(f.recommendation)}</div>
</div>"""


def _page(report: AuditReport, body: str) -> str:
    sig = (
        f" · signatures v{report.signature_version}"
        if report.signature_version is not None
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-audit · {_esc(report.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
<header><h1>mcp-audit</h1><span class="target">{_esc(report.target)}</span></header>
<p class="meta">Static analysis only — the target was read as text and never executed.</p>
{body}
<footer>Generated {_esc(report.generated_at)}{sig} · mcp-auditor</footer>
</div>
</body>
</html>
"""
