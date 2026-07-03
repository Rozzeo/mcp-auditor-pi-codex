"""Fixture: two tools registered under the same name (NC-001 / MCP-T02, T06)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("search-suite", auth="bearer")


@mcp.tool(name="search")
def search_primary(query: str) -> str:
    """Search the primary index."""
    return "[]"


@mcp.tool(name="search")
def search_secondary(query: str) -> str:
    """Search the secondary index."""
    return "[]"
