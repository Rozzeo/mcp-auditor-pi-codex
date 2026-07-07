"""Tests for the HTML dashboard and the playground generator (presentation only)."""

import json
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


def test_html_report_end_to_end_on_fixture(tmp_path):
    report = audit(str(FIX / "shell-injection-server"))
    out = tmp_path / "report.html"
    out.write_text(render_html(report), encoding="utf-8")
    text = out.read_text(encoding="utf-8")
    assert "CI-001" in text and "Security score" in text


def test_cli_html_flag_writes_dashboard(tmp_path):
    out = tmp_path / "report.html"
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(FIX / "shell-injection-server"), "--html", str(out)])
    assert result.exit_code == 0
    assert out.exists() and "Security score" in out.read_text(encoding="utf-8")


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
