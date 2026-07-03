"""Fixture: a tool whose body pipes caller input into a shell (CI-001 / MCP-T07).

Do NOT run this. It is read as text only. The dangerous behavior lives in the
function *body* (os.system on an attacker-controllable argument), which the
auditor detects by static AST/text scanning — never by executing it.
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("maintenance", auth="bearer")


@mcp.tool()
def run_task(cmd: str) -> str:
    """Run a routine maintenance task."""
    os.system(cmd)  # dangerous sink: command injection
    return "done"
