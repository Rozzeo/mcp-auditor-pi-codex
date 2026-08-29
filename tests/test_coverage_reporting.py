"""P1: an audit has to say how much of the target it actually parsed.

A finding count means nothing without it. These cover the two facts that make
the difference legible in the report: which registrations could not be resolved,
and what kind of source files the tree was made of.
"""

import json

from click.testing import CliRunner

from mcp_auditor.cli import main
from mcp_auditor.core import audit


UNRESOLVABLE = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolName, toolConfig } from "./generated/registry.js";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool("read_report", { description: "Read it." }, async () => ({}));
server.registerTool(toolName, toolConfig, async () => ({ content: [] }));
'''


def _server(tmp_path):
    (tmp_path / "index.ts").write_text(UNRESOLVABLE, encoding="utf-8")
    (tmp_path / "__tests__").mkdir()
    (tmp_path / "__tests__" / "index.test.ts").write_text(UNRESOLVABLE, encoding="utf-8")
    return tmp_path


def test_the_report_names_the_registration_it_could_not_resolve(tmp_path):
    report = audit(str(_server(tmp_path)))

    assert report.coverage_gaps is not None
    assert len(report.coverage_gaps) == 1
    gap = report.coverage_gaps[0]
    assert gap["construct"] == "registerTool"
    assert "toolName" in gap["reason"]


def test_the_report_breaks_the_audited_tree_down_by_source_role(tmp_path):
    report = audit(str(_server(tmp_path)))

    assert report.source_roles == {"production": 1, "test": 1}


def test_coverage_facts_survive_json_serialization(tmp_path):
    payload = audit(str(_server(tmp_path))).to_dict()

    assert payload["source_roles"] == {"production": 1, "test": 1}
    assert payload["coverage_gaps"][0]["construct"] == "registerTool"


def test_a_clean_target_reports_no_gaps(tmp_path):
    (tmp_path / "index.ts").write_text(
        UNRESOLVABLE.replace(
            "server.registerTool(toolName, toolConfig, async () => ({ content: [] }));", ""
        ),
        encoding="utf-8",
    )
    payload = audit(str(tmp_path)).to_dict()

    assert "coverage_gaps" not in payload


def test_the_cli_warns_that_a_registration_was_not_resolved(tmp_path):
    result = CliRunner().invoke(main, ["audit", str(_server(tmp_path))])

    assert "unresolved registration" in result.output.lower()


def test_the_json_cli_output_carries_the_same_facts(tmp_path):
    result = CliRunner().invoke(main, ["audit", str(_server(tmp_path)), "--json"])
    payload = json.loads(result.output)

    assert payload["coverage_gaps"][0]["location"].endswith(":8")
    assert payload["source_roles"]["test"] == 1


def test_no_score_is_published_when_a_registration_was_not_resolved(tmp_path):
    """A 0-100 number over a surface that was only partly parsed reads as
    assurance the audit cannot support (spec gate: no safety score when
    coverage is unknown)."""
    report = audit(str(_server(tmp_path)))

    assert report.score is None
    # The contract is that the report says the score was withheld and why, not
    # any particular wording for it.
    assert "withheld" in (report.message or "").lower()


def test_a_fully_resolved_target_still_gets_a_score(tmp_path):
    (tmp_path / "index.ts").write_text(
        UNRESOLVABLE.replace(
            "server.registerTool(toolName, toolConfig, async () => ({ content: [] }));", ""
        ),
        encoding="utf-8",
    )
    report = audit(str(tmp_path))

    assert isinstance(report.score, int)


def test_the_human_report_says_why_the_score_is_withheld(tmp_path):
    result = CliRunner().invoke(main, ["audit", str(_server(tmp_path))])

    assert "score withheld" in result.output.lower()
