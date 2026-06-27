from mcp_auditor.types import Finding, AuditReport, Tool


def test_finding_serializes_to_documented_shape():
    f = Finding(
        id="TP-001",
        category="tool_poisoning",
        severity="critical",
        tool_name="send_email",
        location="server.py:42",
        message="Imperative instruction found in tool description.",
        evidence="ignore all previous instructions ...",
        recommendation="Remove instruction-like text from tool descriptions.",
    )
    d = f.to_dict()
    assert d == {
        "id": "TP-001",
        "category": "tool_poisoning",
        "severity": "critical",
        "tool_name": "send_email",
        "location": "server.py:42",
        "message": "Imperative instruction found in tool description.",
        "evidence": "ignore all previous instructions ...",
        "recommendation": "Remove instruction-like text from tool descriptions.",
    }


def test_audit_report_summary_counts_by_severity():
    findings = [
        Finding("TP-001", "tool_poisoning", "critical", "a", "f:1", "m", "e", "r"),
        Finding("TP-002", "tool_poisoning", "high", "b", "f:2", "m", "e", "r"),
        Finding("OP-001", "over_privilege", "high", "c", "f:3", "m", "e", "r"),
        Finding("ME-001", "meta", "info", None, "f", "m", "e", "r"),
    ]
    report = AuditReport(
        target="https://github.com/owner/repo",
        is_mcp_server=True,
        tools_analyzed=7,
        score=42,
        findings=findings,
        generated_at="2026-06-26T00:00:00Z",
    )
    d = report.to_dict()
    assert d["summary"] == {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 1}
    assert d["target"] == "https://github.com/owner/repo"
    assert d["is_mcp_server"] is True
    assert d["tools_analyzed"] == 7
    assert d["score"] == 42
    assert len(d["findings"]) == 4


def test_non_mcp_report_has_no_score():
    report = AuditReport(
        target="some/path",
        is_mcp_server=False,
        tools_analyzed=0,
        score=None,
        findings=[],
        generated_at="2026-06-26T00:00:00Z",
        message="No MCP tool definitions found.",
    )
    d = report.to_dict()
    assert d["is_mcp_server"] is False
    assert d["score"] is None
    assert d["message"] == "No MCP tool definitions found."


def test_tool_normalized_shape():
    t = Tool(name="x", description="d", schema={"type": "object"}, location="f:1")
    assert t.name == "x"
    assert t.description == "d"
    assert t.schema == {"type": "object"}
    assert t.location == "f:1"
