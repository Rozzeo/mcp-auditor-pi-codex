import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_auditor import audit
from mcp_auditor.cli import main
from mcp_auditor.policy import PolicyError, load_policy, resolve_policy


ROOT = Path(__file__).parents[1]
POLICY = ROOT / "examples" / "department-policy.yaml"

SERVER = r'''
import { McpServer } from "@modelcontextprotocol/server";
import fs from "node:fs/promises";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool(
  "publish",
  { description: "Write and publish output", inputSchema: z.object({ path: z.string() }) },
  async ({ path }) => {
    await fs.writeFile(path, "data");
    await fetch("https://example.test/publish", { method: "POST" });
  }
);
'''


def test_helper_is_narrower_than_main_agent():
    policy = load_policy(POLICY)
    main = resolve_policy(policy, agent="alice-main")
    helper = resolve_policy(policy, agent="alice-helper")

    assert helper.effective_allow < main.effective_allow
    assert helper.effective_allow == {"filesystem.read"}
    assert "filesystem.write" in main.effective_allow
    assert "network.outbound" in main.effective_allow


def test_policy_evaluation_denies_helper_write_and_network(tmp_path):
    server = tmp_path / "server.ts"
    server.write_text(SERVER, encoding="utf-8")
    report = audit(str(server), policy_path=str(POLICY), agent="alice-helper")

    violations = [finding for finding in report.findings if finding.id == "PV-001"]
    assert len(violations) == 2
    assert report.policy["decision"] == "deny"
    assert report.policy["department"] == "engineering"
    assert report.policy["employee"] == "alice"
    assert report.policy["agent"] == "alice-helper"
    assert report.policy["effective_allow"] == ["filesystem.read"]


def test_same_tool_is_allowed_for_main_builder(tmp_path):
    server = tmp_path / "server.ts"
    server.write_text(SERVER, encoding="utf-8")
    report = audit(str(server), policy_path=str(POLICY), agent="alice-main")

    assert not [finding for finding in report.findings if finding.id == "PV-001"]
    assert report.policy["decision"] == "allow"


def test_policy_requires_identity(tmp_path):
    server = tmp_path / "server.ts"
    server.write_text(SERVER, encoding="utf-8")
    with pytest.raises(PolicyError, match="requires --employee or --agent"):
        audit(str(server), policy_path=str(POLICY))


def test_agent_cannot_inherit_across_employees(tmp_path):
    bad = tmp_path / "policy.yaml"
    text = POLICY.read_text(encoding="utf-8")
    text += (
        "\n  bob-helper:\n"
        "    employee: bob\n"
        "    parent: alice-main\n"
        "    profile: reviewer\n"
        "    deny: []\n"
    )
    bad.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError, match="another employee"):
        load_policy(bad)


def test_unknown_capability_is_rejected(tmp_path):
    bad = tmp_path / "policy.yaml"
    text = POLICY.read_text(encoding="utf-8").replace(
        "        - filesystem.read\n", "        - root.takeover\n", 1
    )
    bad.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError, match="unknown capabilities"):
        load_policy(bad)


def test_cli_json_selects_agent_policy(tmp_path):
    server = tmp_path / "server.ts"
    server.write_text(SERVER, encoding="utf-8")
    result = CliRunner().invoke(
        main,
        [str(server), "--json", "--policy", str(POLICY), "--agent", "alice-helper"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["policy"]["decision"] == "deny"
    assert payload["policy"]["agent"] == "alice-helper"
    assert sum(finding["id"] == "PV-001" for finding in payload["findings"]) == 2


def test_cli_human_report_shows_privilege_decision(tmp_path):
    server = tmp_path / "server.ts"
    server.write_text(SERVER, encoding="utf-8")
    result = CliRunner().invoke(
        main,
        [str(server), "--policy", str(POLICY), "--agent", "alice-helper"],
    )
    assert result.exit_code == 0, result.output
    assert "Privilege policy" in result.output
    assert "DENY" in result.output
    assert "filesystem.write" in result.output
