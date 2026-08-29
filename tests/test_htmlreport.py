"""Tests for the HTML dashboard and the playground generator (presentation only)."""

import json
import re
from pathlib import Path

from click.testing import CliRunner

from mcp_auditor.cli import main
from mcp_auditor.core import audit
from mcp_auditor.htmlreport import render_html
from mcp_auditor.playground import build_playground
from mcp_auditor.rules import load_signatures
from mcp_auditor.types import AuditReport, Finding

FIX = Path(__file__).parent / "fixtures"


def _report_with(findings, score=40):
    return AuditReport(
        target="/tmp/example",
        is_mcp_server=True,
        tools_analyzed=2,
        score=score,
        findings=findings,
        generated_at="2026-07-07T00:00:00Z",
        signature_version=4,
    )


def _finding(**over):
    base = dict(
        id="SQ-001",
        category="command_injection",
        severity="critical",
        tool_name="find_user",
        location="server.py:10",
        message="SQL built by interpolation.",
        evidence='f"SELECT * FROM users WHERE name = {name}"',
        recommendation="Use parameterized queries.",
        threat_id="MCP-T07",
        confidence="medium",
    )
    base.update(over)
    return Finding(**base)


# --- render_html -------------------------------------------------------------


def test_html_report_contains_score_and_finding():
    html = render_html(_report_with([_finding()]))
    assert html.startswith("<!doctype html>")
    assert "40" in html and "SQ-001" in html and "MCP-T07" in html
    assert "signatures v4" in html


def test_html_report_escapes_hostile_metadata():
    hostile = _finding(message='<script>alert("x")</script>', evidence="<img src=x>")
    html = render_html(_report_with([hostile]))
    assert "<script>alert" not in html
    assert "<img src=x>" not in html


def test_html_report_marks_suppressed_findings():
    sup = _finding(suppressed=True, suppress_reason="reviewed: test fixture")
    html = render_html(_report_with([sup], score=100))
    assert "Suppressed" in html and "reviewed: test fixture" in html


def test_html_report_handles_non_mcp_target():
    report = AuditReport(
        target="x", is_mcp_server=False, tools_analyzed=0, score=None,
        findings=[], generated_at="2026-07-07T00:00:00Z", message="Not an MCP server.",
    )
    html = render_html(report)
    assert "Not an MCP server" in html


def test_html_report_does_not_label_runtime_capture_as_static():
    report = _report_with([])
    report.evidence_type = "runtime"
    html = render_html(report)
    assert "Runtime evidence" in html
    assert "target was read as text and never executed" not in html


def test_html_report_end_to_end_on_fixture(tmp_path):
    report = audit(str(FIX / "shell-injection-server"))
    out = tmp_path / "report.html"
    out.write_text(render_html(report), encoding="utf-8")
    text = out.read_text(encoding="utf-8")
    assert "CI-001" in text and "Static risk indicator" in text


def test_cli_html_flag_writes_dashboard(tmp_path):
    out = tmp_path / "report.html"
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(FIX / "shell-injection-server"), "--html", str(out)])
    assert result.exit_code == 0
    assert out.exists() and "Static risk indicator" in out.read_text(encoding="utf-8")


def test_html_report_never_turns_no_findings_into_a_safety_claim():
    html = render_html(_report_with([], score=100))

    assert "looks clean" not in html.lower()
    assert "not a universal safety claim" in html.lower()


def test_html_report_withholds_indicator_when_coverage_is_incomplete():
    report = _report_with([], score=None)
    report.message = "Coverage incomplete."

    html = render_html(report)

    assert "withheld" in html.lower()
    assert "0<small>/100" not in html


# --- playground ---------------------------------------------------------------


def test_playground_embeds_current_signature_rules():
    sigs = load_signatures()
    html = build_playground(sigs)
    assert html.startswith("<!doctype html>")
    for rid in ("TP-001", "SQ-001", "DB-001", "DE-001", "DL-001"):
        assert rid in html
    assert f"\"version\": {sigs['version']}" in html or f'"version": {sigs["version"]}' in html


def test_playground_payload_is_valid_json():
    html = build_playground(load_signatures())
    start = html.index("const DATA = ") + len("const DATA = ")
    end = html.index(";\nconst R =", start)
    payload = json.loads(html[start:end].replace("<\\/", "</"))
    assert payload["presets"] and payload["rules"]["SQ-001"]["sql_interp_patterns"]


def test_playground_has_recommendations_panel():
    html = build_playground(load_signatures())
    assert "What to fix first" in html and "renderRecs" in html


def test_cli_playground_command(tmp_path):
    out = tmp_path / "pg.html"
    runner = CliRunner()
    result = runner.invoke(main, ["playground", "--out", str(out)])
    assert result.exit_code == 0
    assert out.exists() and "MCP Security Playground" in out.read_text(encoding="utf-8")


def test_playground_script_declares_every_constant_it_uses():
    """No SCREAMING_CASE identifier may be used without being declared.

    The playground's JS is assembled by string substitution, so renaming a
    Python-side constant can leave a live reference to a name that no longer
    exists. That throws at runtime inside a render path and the page silently
    keeps showing its previous state — which is exactly what happened when
    `SEV_COLOR` was replaced: the score updated and the findings list did not.
    """
    html = build_playground(load_signatures())
    # Start past the embedded DATA blob: it is signature JSON, and its SQL
    # keywords and threat ids are not identifiers.
    script = html[html.index("const R = DATA.rules"):]

    declared = set(re.findall(r"\bconst\s+([A-Z][A-Z0-9_]{2,})\s*=", script))
    # Only indexed or dotted uses — `SEV_COLOR[...]`, `ATTENTION.has(...)`.
    # That is the shape a dead constant reference actually takes. Quoted
    # strings are deliberately NOT stripped first: the references live inside
    # `${...}` in template literals whose HTML attributes carry quotes of their
    # own, and stripping ate exactly the text this test exists to inspect.
    used = set(re.findall(r"\b([A-Z][A-Z0-9_]{2,})\s*[\[.]", script))
    known = {"JSON", "DATA", "Math", "Object", "Array"}

    assert not (used - declared - known), (
        f"playground JS references undeclared constants: {sorted(used - declared - known)}"
    )


def test_playground_substitutes_every_placeholder():
    html = build_playground(load_signatures())
    assert not re.findall(r"__[A-Z][A-Z0-9_]*__", html)
