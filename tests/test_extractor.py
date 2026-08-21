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

PHP_WORDPRESS_ABILITY = r'''<?php
wp_register_ability(
    'mcp-adapter/execute-ability',
    array(
        'label' => 'Execute Ability',
        'description' => 'Execute a public WordPress ability with provided parameters.',
        'input_schema' => array(
            'type' => 'object',
            'properties' => array(
                'ability_name' => array( 'type' => 'string' ),
                'parameters' => array( 'type' => 'object' ),
            ),
            'required' => array( 'ability_name', 'parameters' ),
        ),
        'permission_callback' => array( self::class, 'check_permission' ),
        'execute_callback' => array( self::class, 'execute' ),
        'meta' => array(
            'annotations' => array(
                'readonly' => false,
                'destructive' => true,
                'idempotent' => false,
            ),
        ),
    )
);
'''

PHP_PUBLIC_ABILITY = r'''<?php
wp_register_ability('my-plugin/get-posts', [
    'label' => 'Get Posts',
    'description' => 'Retrieve WordPress posts.',
    'input_schema' => [
        'type' => 'object',
        'properties' => [
            'numberposts' => [ 'type' => 'integer' ],
        ],
    ],
    'meta' => [
        'mcp' => [ 'public' => true, 'type' => 'tool' ],
        'annotations' => [ 'readonly' => true, 'destructive' => false ],
    ],
]);
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


def test_extracts_wordpress_mcp_ability_from_php_adapter_repo():
    result = extract({
        "composer.json": '{"name":"wordpress/mcp-adapter"}',
        "includes/ExecuteAbility.php": PHP_WORDPRESS_ABILITY,
    })

    assert result.is_mcp_server is True
    (tool,) = result.tools
    assert tool.name == "mcp-adapter-execute-ability"
    assert tool.description.startswith("Execute a public WordPress ability")
    assert set(tool.schema["properties"]) == {"ability_name", "parameters"}
    assert tool.annotations == {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
    }
    assert tool.location.startswith("includes/ExecuteAbility.php:")


def test_extracts_explicitly_public_wordpress_mcp_ability_without_adapter_manifest():
    result = extract({"plugin.php": PHP_PUBLIC_ABILITY})

    assert result.is_mcp_server is True
    (tool,) = result.tools
    assert tool.name == "my-plugin-get-posts"
    assert tool.schema["properties"]["numberposts"]["type"] == "integer"
    assert tool.annotations["readOnlyHint"] is True
    assert tool.annotations["destructiveHint"] is False


def test_plain_wordpress_ability_is_not_assumed_to_be_mcp_public():
    source = PHP_PUBLIC_ABILITY.replace("'mcp' => [ 'public' => true, 'type' => 'tool' ],", "")
    result = extract({"plugin.php": source})
    assert result.is_mcp_server is False
    assert result.tools == []


def test_wordpress_php_test_fixtures_are_not_counted_as_operations():
    result = extract({
        "composer.json": '{"name":"wordpress/mcp-adapter"}',
        "tests/phpunit/fixtures/ability.php": PHP_WORDPRESS_ABILITY,
    })
    assert result.is_mcp_server is True
    assert result.tools == []


def test_unrelated_python_tool_decorator_is_not_mcp():
    source = "@app.tool()\ndef format_value(value: str):\n    return value\n"
    result = extract({"app.py": source})
    assert result.is_mcp_server is False
    assert result.tools == []


def test_unrelated_typescript_registration_names_are_not_mcp():
    source = (
        'server.registerTool("hammer", { description: "Workshop item" }, () => 1);\n'
        'router.setRequestHandler("tools/list", handler);\n'
    )
    result = extract({"registry.ts": source})
    assert result.is_mcp_server is False
    assert result.tools == []


def test_mcp_register_tool_allows_custom_server_variable_name():
    source = (
        'import { McpServer } from "@modelcontextprotocol/server";\n'
        'const catalog = new McpServer({ name: "catalog", version: "1" });\n'
        'catalog.registerTool("search", { description: "Search" }, async () => ({}));\n'
    )
    result = extract({"catalog.ts": source})
    assert [tool.name for tool in result.tools] == ["search"]


def test_malformed_python_does_not_crash():
    result = extract({"broken.py": "def (:::", "good.py": PY_FASTMCP})
    # Still finds the good server; broken file is skipped gracefully.
    assert result.is_mcp_server is True
    assert "get_weather" in {t.name for t in result.tools}


def test_ts_body_captures_deep_sink_beyond_old_window():
    # A sink 3000+ chars into the handler must still land in the tool's body.
    padding = "\n".join(f"  const v{i} = {i};" for i in range(300))
    src = (
        'import {} from "@modelcontextprotocol/sdk";\n'
        'server.tool("deep_tool", "A tool with a long handler.", {}, async () => {\n'
        + padding
        + '\n  execSync(userInput);\n});\n'
    )
    result = extract({"server.ts": src})
    (tool,) = result.tools
    assert "execSync" in tool.body


def test_ts_body_does_not_swallow_next_tool():
    # Tool A is tiny; the dangerous sink belongs to tool B and must not be
    # attributed to A (the old fixed window leaked across registrations).
    src = (
        'import {} from "@modelcontextprotocol/sdk";\n'
        'server.tool("tool_a", "Safe tool.", {}, async () => { return 1; });\n'
        'server.tool("tool_b", "Runs things.", {}, async (cmd) => { execSync(cmd); });\n'
    )
    result = extract({"server.ts": src})
    by_name = {t.name: t for t in result.tools}
    assert "execSync" not in by_name["tool_a"].body
    assert "execSync" in by_name["tool_b"].body


def test_ts_body_ignores_paren_inside_string_literal():
    src = (
        'import {} from "@modelcontextprotocol/sdk";\n'
        'server.tool("tool_s", "Has a paren-in-string.", {}, async () => {\n'
        '  const s = ") not the end";\n'
        '  execSync(s);\n'
        '});\n'
    )
    result = extract({"server.ts": src})
    (tool,) = result.tools
    assert "execSync" in tool.body
