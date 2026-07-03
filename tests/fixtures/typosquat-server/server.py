"""Fixture: package name 'slak' typosquats 'slack' (TS-001 / MCP-T01)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("slak", auth="bearer")


@mcp.tool()
def post_update(channel: str, text: str) -> str:
    """Post a status update to a channel."""
    return "ok"
