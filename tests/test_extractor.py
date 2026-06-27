from mcp_auditor.extractor import extract

PY_FASTMCP = '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def get_weather(city: str) -> str:
    """Return the current weather for a city."""
    return "sunny"


@mcp.tool()
def send_email(to: str, body: str) -> str:
    """Send an email to the given recipient."""
    return "sent"
'''

PY_DECORATED_SERVER = '''
from mcp.server import Server

server = Server("demo")


@server.tool()
def read_file(path: str) -> str:
    """Read a file from disk."""
    return open(path).read()
'''

TS_SERVER = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool(
  "list_files",
  "List files in a directory.",
  { dir: z.string() },
  async ({ dir }) => ({ content: [] })
);
'''

MANIFEST = '''
{
  "tools": [
    {
      "name": "search",
      "description": "Search the web for a query.",
      "inputSchema": { "type": "object", "properties": { "q": { "type": "string" } } }
    }
  ]
}
'''

PLAIN_PYTHON = '''
def add(a, b):
    return a + b
'''


def test_detects_python_fastmcp_and_extracts_tools():
    result = extract({"server.py": PY_FASTMCP})
    assert result.is_mcp_server is True
    names = {t.name for t in result.tools}
    assert names == {"get_weather", "send_email"}


def test_python_tool_captures_docstring_as_description():
    result = extract({"server.py": PY_FASTMCP})
    weather = next(t for t in result.tools if t.name == "get_weather")
    assert "weather" in weather.description.lower()


def test_python_tool_records_file_and_line_location():
    result = extract({"server.py": PY_FASTMCP})
    weather = next(t for t in result.tools if t.name == "get_weather")
    assert weather.location.startswith("server.py:")
    assert int(weather.location.split(":")[1]) > 0


def test_python_tool_captures_parameter_schema():
    result = extract({"server.py": PY_FASTMCP})
    email = next(t for t in result.tools if t.name == "send_email")
    props = email.schema.get("properties", {})
    assert "to" in props and "body" in props


def test_detects_server_tool_decorator():
    result = extract({"srv.py": PY_DECORATED_SERVER})
    assert result.is_mcp_server is True
    assert {t.name for t in result.tools} == {"read_file"}


def test_detects_typescript_server_tool():
    result = extract({"index.ts": TS_SERVER})
    assert result.is_mcp_server is True
    tool = next(t for t in result.tools if t.name == "list_files")
    assert "list files" in tool.description.lower()


def test_detects_json_manifest_tools():
    result = extract({"tools.json": MANIFEST})
    assert result.is_mcp_server is True
    tool = next(t for t in result.tools if t.name == "search")
    assert tool.schema["properties"]["q"]["type"] == "string"


def test_plain_repo_is_not_mcp_server():
    result = extract({"util.py": PLAIN_PYTHON})
    assert result.is_mcp_server is False
    assert result.tools == []


def test_malformed_python_does_not_crash():
    result = extract({"broken.py": "def (:::", "good.py": PY_FASTMCP})
    # Still finds the good server; broken file is skipped gracefully.
    assert result.is_mcp_server is True
    assert "get_weather" in {t.name for t in result.tools}
