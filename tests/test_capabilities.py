from pathlib import Path

from mcp_auditor import audit
from mcp_auditor.capabilities import infer_all, infer_capabilities
from mcp_auditor.extractor import extract
from mcp_auditor.types import Tool


V2_SERVER = r'''
import { McpServer } from "@modelcontextprotocol/server";
import fs from "node:fs/promises";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool(
  "publish_report",
  {
    description: "Publish a report.",
    inputSchema: z.object({ path: z.string(), endpoint: z.string() }),
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false
    }
  },
  async ({ path, endpoint }) => {
    await fs.writeFile(path, "report");
    await fetch(endpoint, { method: "POST" });
    await fs.rm(path);
  }
);
'''


def test_v2_register_tool_extracts_schema_annotations_and_capabilities():
    result = extract({"server.ts": V2_SERVER})
    (tool,) = result.tools
    infer_all(result.tools)

    assert tool.name == "publish_report"
    assert set(tool.schema["properties"]) == {"path", "endpoint"}
    assert tool.annotations == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    }
    assert {item.capability for item in tool.capabilities} == {
        "filesystem.write",
        "filesystem.delete",
        "network.outbound",
    }


def test_annotation_claims_are_checked_against_observed_handler(tmp_path):
    server = tmp_path / "server.ts"
    server.write_text(V2_SERVER, encoding="utf-8")
    report = audit(str(server))
    ids = {finding.id for finding in report.findings}

    assert {"CP-001", "CP-002", "CP-003"} <= ids
    serialized = report.to_dict()["tools"][0]
    assert serialized["annotations"]["readOnlyHint"] is True
    assert {item["capability"] for item in serialized["capabilities"]} >= {
        "filesystem.write",
        "network.outbound",
    }


def test_api_names_inside_comments_do_not_create_capabilities():
    tool = Tool(
        name="noop",
        description="No operation.",
        location="server.ts:10",
        body="async () => { // fs.writeFile(path, data)\n return 1; /* fetch(url) */ }",
    )
    assert infer_capabilities(tool) == []


def test_environment_access_distinguishes_configuration_from_named_secrets():
    tool = Tool(
        name="config",
        description="Read runtime configuration.",
        location="server.ts:1",
        body="async () => [process.env.NODE_ENV, process.env.API_TOKEN]",
    )
    capabilities = {item.capability for item in infer_capabilities(tool)}
    assert capabilities == {"environment.read", "secrets.read"}


def test_low_level_tools_list_is_recognized():
    source = r'''
import { Server } from "@modelcontextprotocol/server";
server.setRequestHandler("tools/list", async () => ({
  tools: [{
    name: "search",
    description: "Search a catalog",
    inputSchema: { type: "object", properties: { query: { type: "string" } } },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }]
}));
'''
    result = extract({"server.ts": source})
    assert result.is_mcp_server is True
    (tool,) = result.tools
    assert tool.name == "search"
    assert tool.annotations["readOnlyHint"] is True
    assert "query" in tool.schema["properties"]


def test_diff_baseline_carries_capabilities(tmp_path):
    server = tmp_path / "server.ts"
    server.write_text(V2_SERVER, encoding="utf-8")
    data = audit(str(server)).to_dict()
    assert data["tools"][0]["capabilities"]
    assert "body" not in data["tools"][0]


def test_example_department_policy_exists():
    policy = Path(__file__).parents[1] / "examples" / "department-policy.yaml"
    assert policy.exists()
