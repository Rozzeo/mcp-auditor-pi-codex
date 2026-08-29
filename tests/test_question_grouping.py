"""Ninety-eight identical questions is not a questionnaire.

Being honest about what the engine could not follow is right; emitting one
question per tool when they all share a reason turns the packet into something
nobody reads, which costs the honesty its value.
"""

from mcp_auditor.core import audit
from mcp_auditor.review import build_packet


MANY_TOOLS = "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n" + "".join(
    f'''
from atlassian import Jira

client = Jira(url="https://example.atlassian.net")


@mcp.tool()
def tool_{index}(key: str) -> str:
    """Tool {index}."""
    return client.issue(key)
'''
    for index in range(12)
)


def _packet(tmp_path):
    (tmp_path / "server.py").write_text(MANY_TOOLS, encoding="utf-8")
    return build_packet(audit(str(tmp_path)))


def test_tools_sharing_one_reason_share_one_question(tmp_path):
    packet = _packet(tmp_path)

    assert len(packet["questions"]) == 1


def test_the_question_still_names_the_tools_it_covers(tmp_path):
    question = _packet(tmp_path)["questions"][0]

    assert question["tools"][:2] == ["tool_0", "tool_1"]
    assert len(question["tools"]) == 12
    assert "12 tool" in question["question"]


def test_every_tool_still_gets_its_own_unknown_row(tmp_path):
    """Grouping is for the questionnaire. The matrix stays per tool, because a
    reviewer reads it one tool at a time."""
    packet = _packet(tmp_path)
    unknown = [r for r in packet["capability_matrix"] if r["evidence_status"] == "UNKNOWN"]

    assert len(unknown) == 12


def test_distinct_reasons_stay_distinct(tmp_path):
    source = MANY_TOOLS + '''

@mcp.tool()
def dynamic(action: str) -> str:
    """Dispatch."""
    return handlers[action]()
'''
    (tmp_path / "server.py").write_text(source, encoding="utf-8")
    packet = build_packet(audit(str(tmp_path)))

    assert len(packet["questions"]) == 2
