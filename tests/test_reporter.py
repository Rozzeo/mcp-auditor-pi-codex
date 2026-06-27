import io

from rich.console import Console

from mcp_auditor.reporter import render_human
from mcp_auditor.types import AuditReport, Finding


def render(report) -> str:
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=100)
    render_human(report, console)
    return buf.getvalue()


def test_human_output_shows_score_and_counts():
    report = AuditReport(
        target="srv",
        is_mcp_server=True,
        tools_analyzed=2,
        score=40,
        findings=[Finding("TP-001", "tool_poisoning", "critical", "send_email", "s.py:1", "msg", "ev", "rec")],
        generated_at="2026-06-26T00:00:00Z",
    )
    out = render(report)
    assert "40" in out
    assert "TP-001" in out
    assert "send_email" in out
    assert "critical" in out.lower()


def test_human_output_for_non_mcp_explains_clearly():
    report = AuditReport(
        target="srv",
        is_mcp_server=False,
        tools_analyzed=0,
        score=None,
        findings=[],
        generated_at="2026-06-26T00:00:00Z",
        message="Not an MCP server.",
    )
    out = render(report)
    assert "Not an MCP server." in out
    # No misleading score number presented.
    assert "/100" not in out


def test_human_output_clean_server_celebrates():
    report = AuditReport(
        target="srv",
        is_mcp_server=True,
        tools_analyzed=1,
        score=100,
        findings=[],
        generated_at="2026-06-26T00:00:00Z",
    )
    out = render(report)
    assert "100" in out
    assert "no findings" in out.lower() or "0 findings" in out.lower()
