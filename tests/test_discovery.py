"""Installed-server discovery — reading client configs, never launching them."""

import json

from mcp_auditor.discovery import config_locations, discover, parse_config, to_tools
from mcp_auditor.rules import load_signatures, run_rules

SIGS = load_signatures()

CURSOR = json.dumps({
    "mcpServers": {
        "weather": {"command": "npx", "args": ["-y", "@acme/weather-mcp"],
                    "env": {"WEATHER_API_KEY": "sk-live-9f3a2b7c1d4e5f6a7b8c9d0e"}},
        "notes": {"command": "python", "args": ["-m", "notes_server"]},
        "hosted": {"url": "https://mcp.example.dev/sse"},
    }
})

VSCODE = json.dumps({"servers": {"docs": {"command": "node", "args": ["dist/server.js"]}}})


def test_parses_stdio_and_remote_entries():
    servers = {s.name: s for s in parse_config("Cursor", "/cfg/mcp.json", CURSOR)}
    assert servers["weather"].transport == "stdio"
    assert servers["weather"].launch == "npx -y @acme/weather-mcp"
    assert servers["hosted"].transport == "remote"
    assert servers["hosted"].url == "https://mcp.example.dev/sse"


def test_env_values_never_leave_the_config():
    """Env values are frequently live credentials, so only key names travel."""
    (weather,) = [s for s in parse_config("Cursor", "/cfg/mcp.json", CURSOR) if s.name == "weather"]
    assert weather.env_keys == ["WEATHER_API_KEY"]
    serialized = json.dumps(weather.to_dict())
    assert "sk-live-9f3a2b7c1d4e5f6a7b8c9d0e" not in serialized


def test_vscode_servers_key_is_supported():
    (docs,) = parse_config("VS Code", "/cfg/.vscode/mcp.json", VSCODE)
    assert docs.name == "docs" and docs.launch == "node dist/server.js"


def test_malformed_config_yields_nothing_instead_of_raising():
    assert parse_config("Cursor", "/cfg/mcp.json", "{not json") == []


def test_fetch_and_run_launch_spec_is_flagged():
    """`npx -y <pkg>` re-downloads and executes the package on every start, so
    the existing XC-001 rule applies to a launch spec without being duplicated."""
    tools = to_tools(parse_config("Cursor", "/cfg/mcp.json", CURSOR))
    found = {(f.id, f.tool_name) for f in run_rules(tools, SIGS, has_auth_signal=True)}
    assert ("XC-001", "weather") in found
    assert not any(name == "notes" for _, name in found)


def test_credentials_pasted_into_a_config_are_flagged():
    findings = run_rules([], SIGS, has_auth_signal=True, files={"/cfg/mcp.json": CURSOR})
    assert "CR-001" in {f.id for f in findings}


def test_discover_reads_project_and_home_configs(tmp_path):
    home, cwd = tmp_path / "home", tmp_path / "proj"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(CURSOR, encoding="utf-8")
    (cwd / ".vscode").mkdir(parents=True)
    (cwd / ".vscode" / "mcp.json").write_text(VSCODE, encoding="utf-8")

    servers, texts = discover(home=home, cwd=cwd)
    assert {s.name for s in servers} == {"weather", "notes", "hosted", "docs"}
    assert len(texts) == 2


def test_discover_is_quiet_when_nothing_is_installed(tmp_path):
    servers, texts = discover(home=tmp_path / "home", cwd=tmp_path / "proj")
    assert servers == [] and texts == {}


def test_claude_desktop_location_is_platform_specific(tmp_path):
    def path_for(platform):
        locations = dict((client, p) for client, p in config_locations(tmp_path, tmp_path, platform))
        return str(locations["Claude Desktop"])

    assert "Application Support" in path_for("darwin")
    assert ".config" in path_for("linux")
