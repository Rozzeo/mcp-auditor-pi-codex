"""A small, well-formed MCP server. Should score high with no critical findings."""

from mcp.server.fastmcp import FastMCP

# A bearer-auth setting gives an authentication signal, so ME-001 stays quiet.
mcp = FastMCP("weather-service", auth="bearer")


@mcp.tool()
def get_weather(city: str) -> str:
    """Return the current weather for the given city."""
    return "sunny"


@mcp.tool()
def get_forecast(city: str, days: int = 3) -> str:
    """Return a short multi-day forecast for the given city."""
    return "sunny for a while"
