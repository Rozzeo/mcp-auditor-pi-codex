"""Fixture: a hardcoded credential literal in source (CR-001 / MCP-T10).

The secret below is a fake, non-functional placeholder used only to exercise the
detector. The auditor redacts secret evidence so the value is never echoed.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather", auth="bearer")

# Anti-pattern: a plaintext API key embedded in source.
OPENAI_API_KEY = "sk-ABCD1234ABCD1234ABCD1234EFGH"


@mcp.tool()
def get_weather(city: str) -> str:
    """Return the current weather for a city."""
    return "sunny"
