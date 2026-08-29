"""An effect behind a package boundary is unknown, not absent.

The call graph stops at the edge of the repository on purpose. But a handler
that calls `atlassian.jira.get_issue(...)` or `chromadb` then produces an empty
capability list, and an empty list reads as "this tool does nothing" — which is
the single most dangerous thing this report can say about a tool it did not
actually analyse.

Silence and "no effects" have to be distinguishable.
"""

from mcp_auditor.capabilities import infer_all
from mcp_auditor.extractor import extract


PY_HEADER = "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n"

THIRD_PARTY = PY_HEADER + '''
from atlassian import Jira

client = Jira(url="https://example.atlassian.net")


@mcp.tool()
def get_issue(issue_key: str) -> str:
    """Get an issue."""
    return client.issue(issue_key)
'''

PURE = PY_HEADER + '''
@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''

RESOLVED = PY_HEADER + '''
def _persist(path, body):
    with open(path, "w") as fh:
        fh.write(body)


@mcp.tool()
def save(path: str, body: str) -> str:
    """Save a note."""
    _persist(path, body)
    return "ok"
'''


def _tool(source: str):
    files = {"server.py": source}
    extraction = extract(files)
    infer_all(extraction.tools, files=files)
    return extraction.tools[0]


def test_a_call_into_a_third_party_package_is_recorded_as_unknown():
    tool = _tool(THIRD_PARTY)

    assert tool.capabilities == []
    assert any("atlassian" in note for note in tool.unresolved_calls)


def test_a_tool_that_genuinely_does_nothing_stays_silent():
    """Arithmetic is arithmetic. An unknown here would be noise, and noise in
    this field is what makes a reviewer stop reading it."""
    tool = _tool(PURE)

    assert tool.capabilities == []
    assert tool.unresolved_calls == []


def test_a_call_the_walk_resolved_is_not_also_reported_unknown():
    tool = _tool(RESOLVED)

    assert {e.capability for e in tool.capabilities} == {"filesystem.write"}
    assert tool.unresolved_calls == []


def test_the_review_packet_turns_the_boundary_into_a_question(tmp_path):
    from mcp_auditor.core import audit
    from mcp_auditor.review import build_packet

    (tmp_path / "server.py").write_text(THIRD_PARTY, encoding="utf-8")
    packet = build_packet(audit(str(tmp_path)))

    row = next(r for r in packet["capability_matrix"] if r["tool"] == "get_issue")
    assert row["evidence_status"] == "UNKNOWN"
    assert any("get_issue" in q["question"] for q in packet["questions"])
