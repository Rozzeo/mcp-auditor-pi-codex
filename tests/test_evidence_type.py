"""Evidence levels must not flatter the input (spec §3).

Source, declared metadata, a runtime capture and a vendor page establish very
different things. A page of prose describing an MCP server proves nothing about
its implementation, and calling that "source" invites exactly the overstatement
the review packet exists to prevent.
"""

from mcp_auditor.core import audit


def test_a_prose_only_target_is_documentation(tmp_path):
    (tmp_path / "TOOLS.md").write_text(
        "# Tools\n\nThe server exposes `read_note` and `purge_note`.\n", encoding="utf-8"
    )

    assert audit(str(tmp_path)).evidence_type == "documentation"


def test_source_alongside_documentation_is_still_source(tmp_path):
    (tmp_path / "README.md").write_text("# Server\n", encoding="utf-8")
    (tmp_path / "index.ts").write_text(
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'server.registerTool("t", { description: "d" }, async () => ({}));\n',
        encoding="utf-8",
    )

    assert audit(str(tmp_path)).evidence_type == "source"


def test_an_agent_skill_is_not_mere_documentation(tmp_path):
    """A SKILL.md is the thing that runs, not a description of it."""
    skill = tmp_path / "my-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: my-skill\ndescription: Does a thing.\n---\n\nRun the thing.\n",
        encoding="utf-8",
    )

    assert audit(str(tmp_path)).evidence_type == "source"


def test_a_runtime_capture_still_outranks_everything(tmp_path):
    (tmp_path / "capture.json").write_text(
        '{"capture_kind": "wordpress-runtime", "tools": []}', encoding="utf-8"
    )

    assert audit(str(tmp_path)).evidence_type == "runtime"
