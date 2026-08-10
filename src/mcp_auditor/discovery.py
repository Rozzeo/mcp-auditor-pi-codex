"""Installed-server discovery: what MCP servers a machine is actually wired to.

Auditing a repository answers "is this server safe?". This module answers the
question that comes first in practice — "what is this employee's agent already
allowed to call?" — by reading the well-known MCP client config files and
listing every server registered in them.

Config files are read as TEXT and parsed as JSON. Nothing is launched: the
`command`/`args` of a stdio server are treated purely as evidence, and a remote
server's URL is never contacted. That keeps discovery inside the same
static-only guarantee as the rest of the tool.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .types import Tool

# Both spellings are in the wild: most clients nest servers under `mcpServers`,
# VS Code uses `servers` in .vscode/mcp.json.
_SERVER_KEYS = ("mcpServers", "servers")


@dataclass
class InstalledServer:
    """One MCP server registered in a client config."""

    client: str
    name: str
    source: str
    transport: str  # "stdio" | "remote"
    launch: str = ""  # command + args, for a stdio server
    url: str = ""  # endpoint, for a remote server
    env_keys: list[str] = field(default_factory=list)  # names only, never values

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "client": self.client,
            "name": self.name,
            "source": self.source,
            "transport": self.transport,
        }
        if self.launch:
            out["launch"] = self.launch
        if self.url:
            out["url"] = self.url
        if self.env_keys:
            out["env_keys"] = self.env_keys
        return out


def config_locations(home: Path, cwd: Path, platform: str | None = None) -> list[tuple[str, Path]]:
    """Well-known client config paths for this platform, plus project-local ones."""
    plat = platform or sys.platform
    if plat.startswith("win"):
        appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
        claude_desktop = appdata / "Claude" / "claude_desktop_config.json"
    elif plat == "darwin":
        claude_desktop = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        claude_desktop = home / ".config" / "Claude" / "claude_desktop_config.json"

    return [
        ("Claude Desktop", claude_desktop),
        ("Claude Code", home / ".claude.json"),
        ("Claude Code (project)", cwd / ".mcp.json"),
        ("Cursor", home / ".cursor" / "mcp.json"),
        ("Cursor (project)", cwd / ".cursor" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("VS Code (project)", cwd / ".vscode" / "mcp.json"),
    ]


def parse_config(client: str, source: str, text: str) -> list[InstalledServer]:
    """Extract registered servers from one config file's text.

    Returns an empty list for malformed JSON rather than raising: one broken
    config must never hide the servers registered in every other one.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    entries: dict[str, Any] = {}
    for key in _SERVER_KEYS:
        section = data.get(key)
        if isinstance(section, dict):
            entries.update(section)

    servers: list[InstalledServer] = []
    for name, spec in entries.items():
        if not isinstance(spec, dict):
            continue
        url = spec.get("url") or spec.get("serverUrl") or ""
        command = spec.get("command") or ""
        args = spec.get("args") if isinstance(spec.get("args"), list) else []
        launch = " ".join([str(command), *(str(a) for a in args)]).strip()
        env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
        servers.append(
            InstalledServer(
                client=client,
                name=str(name),
                source=source,
                transport="remote" if url and not command else "stdio",
                launch=launch,
                url=str(url) if url else "",
                # Values can be live credentials; only the key names travel.
                env_keys=sorted(str(k) for k in env),
            )
        )
    return servers


def discover(home: Path | None = None, cwd: Path | None = None) -> tuple[list[InstalledServer], dict[str, str]]:
    """Find every registered server. Returns (servers, {config path: text}).

    The raw config text is returned alongside so file-level rules — CR-001 in
    particular — can scan it for credentials pasted into an `env` block.
    """
    home = home or Path(os.path.expanduser("~"))
    cwd = cwd or Path.cwd()
    servers: list[InstalledServer] = []
    texts: dict[str, str] = {}
    for client, path in config_locations(home, cwd):
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        source = str(path)
        texts[source] = text
        servers.extend(parse_config(client, source, text))
    return servers, texts


def to_tools(servers: Iterable[InstalledServer]) -> list[Tool]:
    """Represent each registered server as a Tool so the existing rule engine
    can read its launch spec.

    The launch command lands in `body`, which is what the code-level rules
    scan — so XC-001 flags a server that fetches and runs remote code on every
    start (`npx -y <pkg>`, `curl | bash`) without a rule being duplicated here.
    """
    tools: list[Tool] = []
    for server in servers:
        detail = server.launch or server.url
        tools.append(
            Tool(
                name=server.name,
                description=f"{server.client} registered server: {detail}",
                schema={},
                location=server.source,
                body=detail,
            )
        )
    return tools
